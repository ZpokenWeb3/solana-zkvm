//! The `metrics` module enables sending measurements to an `InfluxDB` instance

use {
    crate::{counter::CounterPoint, datapoint::DataPoint},
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    gethostname::gethostname,
    lazy_static::lazy_static,
    log::*,
    solana_sdk::{genesis_config::ClusterType, hash::hash},
    std::{
        cmp,
        collections::HashMap,
        convert::Into,
        env,
        fmt::Write,
        sync::{Arc, Barrier, Mutex, Once, RwLock},
        thread,
        time::{Duration, Instant, UNIX_EPOCH},
    },
    thiserror::Error,
};

type CounterMap = HashMap<(&'static str, u64), CounterPoint>;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error(transparent)]
    VarError(#[from] env::VarError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("SOLANA_METRICS_CONFIG is invalid: '{0}'")]
    ConfigInvalid(String),
    #[error("SOLANA_METRICS_CONFIG is incomplete")]
    ConfigIncomplete,
    #[error("SOLANA_METRICS_CONFIG database mismatch: {0}")]
    DbMismatch(String),
}

impl From<MetricsError> for String {
    fn from(error: MetricsError) -> Self {
        error.to_string()
    }
}

impl From<&CounterPoint> for DataPoint {
    fn from(counter_point: &CounterPoint) -> Self {
        let mut point = Self::new(counter_point.name);
        point.timestamp = counter_point.timestamp;
        point.add_field_i64("count", counter_point.count);
        point
    }
}

#[derive(Debug)]
enum MetricsCommand {
    Flush(Arc<Barrier>),
    Submit(DataPoint, log::Level),
    SubmitCounter(CounterPoint, log::Level, u64),
}

pub struct MetricsAgent {
    sender: Sender<MetricsCommand>,
}

pub trait MetricsWriter {
    // Write the points and empty the vector.  Called on the internal
    // MetricsAgent worker thread.
    fn write(&self, points: Vec<DataPoint>);
}

struct InfluxDbMetricsWriter {
    write_url: Option<String>,
}

impl InfluxDbMetricsWriter {
    fn new() -> Self {
        Self {
            write_url: Self::build_write_url().ok(),
        }
    }

    fn build_write_url() -> Result<String, MetricsError> {
        let config = get_metrics_config().map_err(|err| {
            info!("metrics disabled: {}", err);
            err
        })?;

        info!(
            "metrics configuration: host={} db={} username={}",
            config.host, config.db, config.username
        );

        let write_url = format!(
            "{}/write?db={}&u={}&p={}&precision=n",
            &config.host, &config.db, &config.username, &config.password
        );

        Ok(write_url)
    }
}

pub fn serialize_points(points: &Vec<DataPoint>, host_id: &str) -> String {
    const TIMESTAMP_LEN: usize = 20;
    const HOST_ID_LEN: usize = 8; // "host_id=".len()
    const EXTRA_LEN: usize = 2; // "=,".len()
    let mut len = 0;
    for point in points {
        for (name, value) in &point.fields {
            len += name.len() + value.len() + EXTRA_LEN;
        }
        for (name, value) in &point.tags {
            len += name.len() + value.len() + EXTRA_LEN;
        }
        len += point.name.len();
        len += TIMESTAMP_LEN;
        len += host_id.len() + HOST_ID_LEN;
    }
    let mut line = String::with_capacity(len);
    for point in points {
        let _ = write!(line, "{},host_id={}", &point.name, host_id);
        for (name, value) in point.tags.iter() {
            let _ = write!(line, ",{name}={value}");
        }

        let mut first = true;
        for (name, value) in point.fields.iter() {
            let _ = write!(line, "{}{}={}", if first { ' ' } else { ',' }, name, value);
            first = false;
        }
        let timestamp = point.timestamp.duration_since(UNIX_EPOCH);
        let nanos = timestamp.unwrap().as_nanos();
        let _ = writeln!(line, " {nanos}");
    }
    line
}

impl MetricsWriter for InfluxDbMetricsWriter {
    fn write(&self, points: Vec<DataPoint>) {
        if let Some(ref write_url) = self.write_url {
            debug!("submitting {} points", points.len());

            let host_id = HOST_ID.read().unwrap();

            let line = serialize_points(&points, &host_id);

            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build();
            let client = match client {
                Ok(client) => client,
                Err(err) => {
                    warn!("client instantiation failed: {}", err);
                    return;
                }
            };

            let response = client.post(write_url.as_str()).body(line).send();
            if let Ok(resp) = response {
                let status = resp.status();
                if !status.is_success() {
                    let text = resp
                        .text()
                        .unwrap_or_else(|_| "[text body empty]".to_string());
                    warn!("submit response unsuccessful: {} {}", status, text,);
                }
            } else {
                warn!("submit error: {}", response.unwrap_err());
            }
        }
    }
}

impl Default for MetricsAgent {
    fn default() -> Self {
        let max_points_per_sec = env::var("SOLANA_METRICS_MAX_POINTS_PER_SECOND")
            .map(|x| {
                x.parse()
                    .expect("Failed to parse SOLANA_METRICS_MAX_POINTS_PER_SECOND")
            })
            .unwrap_or(4000);

        Self::new(
            Arc::new(InfluxDbMetricsWriter::new()),
            Duration::from_secs(10),
            max_points_per_sec,
        )
    }
}

impl MetricsAgent {
    pub fn new(
        writer: Arc<dyn MetricsWriter + Send + Sync>,
        write_frequency: Duration,
        max_points_per_sec: usize,
    ) -> Self {
        let (sender, receiver) = unbounded::<MetricsCommand>();

        thread::Builder::new()
            .name("solMetricsAgent".into())
            .spawn(move || Self::run(&receiver, &writer, write_frequency, max_points_per_sec))
            .unwrap();

        Self { sender }
    }

    // Combines `points` and `counters` into a single array of `DataPoint`s, appending a data point
    // with the metrics stats at the end.
    //
    // Limits the number of produced points to the `max_points` value.  Takes `points` followed by
    // `counters`, dropping `counters` first.
    //
    // `max_points_per_sec` is only used in a warning message.
    // `points_buffered` is used in the stats.
    fn combine_points(
        max_points: usize,
        max_points_per_sec: usize,
        secs_since_last_write: u64,
        points_buffered: usize,
        points: &mut Vec<DataPoint>,
        counters: &mut CounterMap,
    ) -> Vec<DataPoint> {
        // Reserve one slot for the stats point we will add at the end.
        let max_points = max_points.saturating_sub(1);

        let num_points = points.len().saturating_add(counters.len());
        let fit_counters = max_points.saturating_sub(points.len());
        let points_written = cmp::min(num_points, max_points);

        debug!("run: attempting to write {} points", num_points);

        if num_points > max_points {
            warn!(
                "Max submission rate of {} datapoints per second exceeded.  Only the \
                 first {} of {} points will be submitted.",
                max_points_per_sec, max_points, num_points
            );
        }

        let mut combined = std::mem::take(points);
        combined.truncate(points_written);

        combined.extend(counters.values().take(fit_counters).map(|v| v.into()));
        counters.clear();

        combined.push(
            DataPoint::new("metrics")
                .add_field_i64("points_written", points_written as i64)
                .add_field_i64("num_points", num_points as i64)
                .add_field_i64("points_lost", (num_points - points_written) as i64)
                .add_field_i64("points_buffered", points_buffered as i64)
                .add_field_i64("secs_since_last_write", secs_since_last_write as i64)
                .to_owned(),
        );

        combined
    }

    // Consumes provided `points`, sending up to `max_points` of them into the `writer`.
    //
    // Returns an updated value for `last_write_time`.  Which is equal to `Instant::now()`, just
    // before `write` in updated.
    fn write(
        writer: &Arc<dyn MetricsWriter + Send + Sync>,
        max_points: usize,
        max_points_per_sec: usize,
        last_write_time: Instant,
        points_buffered: usize,
        points: &mut Vec<DataPoint>,
        counters: &mut CounterMap,
    ) -> Instant {
        let now = Instant::now();
        let secs_since_last_write = now.duration_since(last_write_time).as_secs();

        writer.write(Self::combine_points(
            max_points,
            max_points_per_sec,
            secs_since_last_write,
            points_buffered,
            points,
            counters,
        ));

        now
    }

    fn run(
        receiver: &Receiver<MetricsCommand>,
        writer: &Arc<dyn MetricsWriter + Send + Sync>,
        write_frequency: Duration,
        max_points_per_sec: usize,
    ) {
        trace!("run: enter");
        let mut last_write_time = Instant::now();
        let mut points = Vec::<DataPoint>::new();
        let mut counters = CounterMap::new();

        let max_points = write_frequency.as_secs() as usize * max_points_per_sec;

        // Bind common arguments in the `Self::write()` call.
        let write = |last_write_time: Instant,
                     points: &mut Vec<DataPoint>,
                     counters: &mut CounterMap|
         -> Instant {
            Self::write(
                writer,
                max_points,
                max_points_per_sec,
                last_write_time,
                receiver.len(),
                points,
                counters,
            )
        };

        loop {
            match receiver.recv_timeout(write_frequency / 2) {
                Ok(cmd) => match cmd {
                    MetricsCommand::Flush(barrier) => {
                        debug!("metrics_thread: flush");
                        last_write_time = write(last_write_time, &mut points, &mut counters);
                        barrier.wait();
                    }
                    MetricsCommand::Submit(point, level) => {
                        log!(level, "{}", point);
                        points.push(point);
                    }
                    MetricsCommand::SubmitCounter(counter, _level, bucket) => {
                        debug!("{:?}", counter);
                        let key = (counter.name, bucket);
                        if let Some(value) = counters.get_mut(&key) {
                            value.count += counter.count;
                        } else {
                            counters.insert(key, counter);
                        }
                    }
                },
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    debug!("run: sender disconnected");
                    break;
                }
            }

            let now = Instant::now();
            if now.duration_since(last_write_time) >= write_frequency {
                last_write_time = write(last_write_time, &mut points, &mut counters);
            }
        }

        debug_assert!(
            points.is_empty() && counters.is_empty(),
            "Controlling `MetricsAgent` is expected to call `flush()` from the `Drop` \n\
             implementation, before exiting.  So both `points` and `counters` must be empty at \n\
             this point.\n\
             `points`: {points:?}\n\
             `counters`: {counters:?}",
        );

        trace!("run: exit");
    }

    pub fn submit(&self, point: DataPoint, level: log::Level) {
        self.sender
            .send(MetricsCommand::Submit(point, level))
            .unwrap();
    }

    pub fn submit_counter(&self, counter: CounterPoint, level: log::Level, bucket: u64) {
        self.sender
            .send(MetricsCommand::SubmitCounter(counter, level, bucket))
            .unwrap();
    }

    pub fn flush(&self) {
        debug!("Flush");
        let barrier = Arc::new(Barrier::new(2));
        self.sender
            .send(MetricsCommand::Flush(Arc::clone(&barrier)))
            .unwrap();

        barrier.wait();
    }
}

impl Drop for MetricsAgent {
    fn drop(&mut self) {
        self.flush();
    }
}

fn get_singleton_agent() -> &'static MetricsAgent {
    lazy_static! {
        static ref AGENT: MetricsAgent = MetricsAgent::default();
    };

    &AGENT
}

lazy_static! {
    static ref HOST_ID: Arc<RwLock<String>> = {
        Arc::new(RwLock::new({
            let hostname: String = gethostname()
                .into_string()
                .unwrap_or_else(|_| "".to_string());
            format!("{}", hash(hostname.as_bytes()))
        }))
    };
}

pub fn set_host_id(host_id: String) {
    info!("host id: {}", host_id);
    *HOST_ID.write().unwrap() = host_id;
}

/// Submits a new point from any thread.  Note that points are internally queued
/// and transmitted periodically in batches.
pub fn submit(point: DataPoint, level: log::Level) {
    let agent = get_singleton_agent();
    agent.submit(point, level);
}

/// Submits a new counter or updates an existing counter from any thread.  Note that points are
/// internally queued and transmitted periodically in batches.
pub(crate) fn submit_counter(point: CounterPoint, level: log::Level, bucket: u64) {
    let agent = get_singleton_agent();
    agent.submit_counter(point, level, bucket);
}

#[derive(Debug, Default)]
struct MetricsConfig {
    pub host: String,
    pub db: String,
    pub username: String,
    pub password: String,
}

impl MetricsConfig {
    fn complete(&self) -> bool {
        !(self.host.is_empty()
            || self.db.is_empty()
            || self.username.is_empty()
            || self.password.is_empty())
    }
}

fn get_metrics_config() -> Result<MetricsConfig, MetricsError> {
    let mut config = MetricsConfig::default();
    let config_var = env::var("SOLANA_METRICS_CONFIG")?;
    if config_var.is_empty() {
        Err(env::VarError::NotPresent)?;
    }

    for pair in config_var.split(',') {
        let nv: Vec<_> = pair.split('=').collect();
        if nv.len() != 2 {
            return Err(MetricsError::ConfigInvalid(pair.to_string()));
        }
        let v = nv[1].to_string();
        match nv[0] {
            "host" => config.host = v,
            "db" => config.db = v,
            "u" => config.username = v,
            "p" => config.password = v,
            _ => return Err(MetricsError::ConfigInvalid(pair.to_string())),
        }
    }

    if !config.complete() {
        return Err(MetricsError::ConfigIncomplete);
    }

    Ok(config)
}

pub fn metrics_config_sanity_check(cluster_type: ClusterType) -> Result<(), MetricsError> {
    let config = match get_metrics_config() {
        Ok(config) => config,
        Err(MetricsError::VarError(env::VarError::NotPresent)) => return Ok(()),
        Err(e) => return Err(e),
    };
    match &config.db[..] {
        "mainnet-beta" if cluster_type != ClusterType::MainnetBeta => (),
        "tds" if cluster_type != ClusterType::Testnet => (),
        "devnet" if cluster_type != ClusterType::Devnet => (),
        _ => return Ok(()),
    };
    let (host, db) = (&config.host, &config.db);
    let msg = format!("cluster_type={cluster_type:?} host={host} database={db}");
    Err(MetricsError::DbMismatch(msg))
}

pub fn query(q: &str) -> Result<String, MetricsError> {
    let config = get_metrics_config()?;
    let query_url = format!(
        "{}/query?u={}&p={}&q={}",
        &config.host, &config.username, &config.password, &q
    );

    let response = reqwest::blocking::get(query_url.as_str())?.text()?;

    Ok(response)
}

/// Blocks until all pending points from previous calls to `submit` have been
/// transmitted.
pub fn flush() {
    let agent = get_singleton_agent();
    agent.flush();
}

/// Hook the panic handler to generate a data point on each panic
pub fn set_panic_hook(program: &'static str, version: Option<String>) {
    static SET_HOOK: Once = Once::new();
    SET_HOOK.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |ono| {
            default_hook(ono);
            let location = match ono.location() {
                Some(location) => location.to_string(),
                None => "?".to_string(),
            };
            submit(
                DataPoint::new("panic")
                    .add_field_str("program", program)
                    .add_field_str("thread", thread::current().name().unwrap_or("?"))
                    // The 'one' field exists to give Kapacitor Alerts a numerical value
                    // to filter on
                    .add_field_i64("one", 1)
                    .add_field_str("message", &ono.to_string())
                    .add_field_str("location", &location)
                    .add_field_str("version", version.as_ref().unwrap_or(&"".to_string()))
                    .to_owned(),
                Level::Error,
            );
            // Flush metrics immediately
            flush();

            // Exit cleanly so the process don't limp along in a half-dead state
            std::process::exit(1);
        }));
    });
}

pub mod test_mocks {
    use super::*;

    pub struct MockMetricsWriter {
        pub points_written: Arc<Mutex<Vec<DataPoint>>>,
    }
    impl MockMetricsWriter {
        pub fn new() -> Self {
            MockMetricsWriter {
                points_written: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn points_written(&self) -> usize {
            self.points_written.lock().unwrap().len()
        }
    }

    impl Default for MockMetricsWriter {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MetricsWriter for MockMetricsWriter {
        fn write(&self, points: Vec<DataPoint>) {
            assert!(!points.is_empty());

            let new_points = points.len();
            self.points_written.lock().unwrap().extend(points);

            info!(
                "Writing {} points ({} total)",
                new_points,
                self.points_written(),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use {super::*, test_mocks::MockMetricsWriter};

    #[test]
    fn test_submit() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(10), 1000);

        for i in 0..42 {
            agent.submit(
                DataPoint::new("measurement")
                    .add_field_i64("i", i)
                    .to_owned(),
                Level::Info,
            );
        }

        agent.flush();
        assert_eq!(writer.points_written(), 43);
    }

    #[test]
    fn test_submit_counter() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(10), 1000);

        for i in 0..10 {
            agent.submit_counter(CounterPoint::new("counter 1"), Level::Info, i);
            agent.submit_counter(CounterPoint::new("counter 2"), Level::Info, i);
        }

        agent.flush();
        assert_eq!(writer.points_written(), 21);
    }

    #[test]
    fn test_submit_counter_increment() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(10), 1000);

        for _ in 0..10 {
            agent.submit_counter(
                CounterPoint {
                    name: "counter",
                    count: 10,
                    timestamp: UNIX_EPOCH,
                },
                Level::Info,
                0, // use the same bucket
            );
        }

        agent.flush();
        assert_eq!(writer.points_written(), 2);

        let submitted_point = writer.points_written.lock().unwrap()[0].clone();
        assert_eq!(submitted_point.fields[0], ("count", "100i".to_string()));
    }

    #[test]
    fn test_submit_bucketed_counter() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(10), 1000);

        for i in 0..50 {
            agent.submit_counter(CounterPoint::new("counter 1"), Level::Info, i / 10);
            agent.submit_counter(CounterPoint::new("counter 2"), Level::Info, i / 10);
        }

        agent.flush();
        assert_eq!(writer.points_written(), 11);
    }

    #[test]
    fn test_submit_with_delay() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(1), 1000);

        agent.submit(DataPoint::new("point 1"), Level::Info);
        thread::sleep(Duration::from_secs(2));
        assert_eq!(writer.points_written(), 2);
    }

    #[test]
    fn test_submit_exceed_max_rate() {
        let writer = Arc::new(MockMetricsWriter::new());

        let max_points_per_sec = 100;

        let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(1), max_points_per_sec);

        for i in 0..(max_points_per_sec + 20) {
            agent.submit(
                DataPoint::new("measurement")
                    .add_field_i64("i", i.try_into().unwrap())
                    .to_owned(),
                Level::Info,
            );
        }

        thread::sleep(Duration::from_secs(2));

        agent.flush();

        // We are expecting `max_points_per_sec - 1` data points from `submit()` and two more metric
        // stats data points.  One from the timeout when all the `submit()`ed values are sent when 1
        // second is elapsed, and then one more from the explicit `flush()`.
        assert_eq!(writer.points_written(), max_points_per_sec + 1);
    }

    #[test]
    fn test_multithread_submit() {
        let writer = Arc::new(MockMetricsWriter::new());
        let agent = Arc::new(Mutex::new(MetricsAgent::new(
            writer.clone(),
            Duration::from_secs(10),
            1000,
        )));

        //
        // Submit measurements from different threads
        //
        let mut threads = Vec::new();
        for i in 0..42 {
            let mut point = DataPoint::new("measurement");
            point.add_field_i64("i", i);
            let agent = Arc::clone(&agent);
            threads.push(thread::spawn(move || {
                agent.lock().unwrap().submit(point, Level::Info);
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }

        agent.lock().unwrap().flush();
        assert_eq!(writer.points_written(), 43);
    }

    #[test]
    fn test_flush_before_drop() {
        let writer = Arc::new(MockMetricsWriter::new());
        {
            let agent = MetricsAgent::new(writer.clone(), Duration::from_secs(9_999_999), 1000);
            agent.submit(DataPoint::new("point 1"), Level::Info);
        }

        // The datapoints we expect to see are:
        // 1. `point 1` from the above.
        // 2. `metrics` stats submitted as a result of the `Flush` sent by `agent` being destroyed.
        assert_eq!(writer.points_written(), 2);
    }

    #[test]
    fn test_live_submit() {
        let agent = MetricsAgent::default();

        let point = DataPoint::new("live_submit_test")
            .add_field_bool("true", true)
            .add_field_bool("random_bool", rand::random::<u8>() < 128)
            .add_field_i64("random_int", rand::random::<u8>() as i64)
            .to_owned();
        agent.submit(point, Level::Info);
    }
}
