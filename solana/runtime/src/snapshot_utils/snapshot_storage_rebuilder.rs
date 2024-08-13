//! Provides interfaces for rebuilding snapshot storages

use {
    super::{snapshot_version_from_file, SnapshotError, SnapshotFrom, SnapshotVersion},
    crate::serde_snapshot::{
        self, reconstruct_single_storage, remap_and_reconstruct_single_storage,
        snapshot_storage_lengths_from_fields, SerializedAccountsFileId,
    },
    crossbeam_channel::{select, unbounded, Receiver, Sender},
    dashmap::DashMap,
    log::*,
    rayon::{
        iter::{IntoParallelIterator, ParallelIterator},
        ThreadPool, ThreadPoolBuilder,
    },
    regex::Regex,
    solana_accounts_db::{
        account_storage::{AccountStorageMap, AccountStorageReference},
        accounts_db::{AccountStorageEntry, AccountsFileId, AtomicAccountsFileId},
        accounts_file::StorageAccess,
    },
    solana_sdk::clock::Slot,
    std::{
        collections::HashMap,
        fs::File,
        io::{BufReader, Error as IoError},
        path::PathBuf,
        str::FromStr as _,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Instant,
    },
};

lazy_static! {
    static ref VERSION_FILE_REGEX: Regex = Regex::new(r"^version$").unwrap();
    static ref BANK_FIELDS_FILE_REGEX: Regex = Regex::new(r"^[0-9]+(\.pre)?$").unwrap();
}

/// Convenient wrapper for snapshot version and rebuilt storages
pub(crate) struct RebuiltSnapshotStorage {
    /// Snapshot version
    pub snapshot_version: SnapshotVersion,
    /// Rebuilt storages
    pub storage: AccountStorageMap,
}

/// Stores state for rebuilding snapshot storages
#[derive(Debug)]
pub(crate) struct SnapshotStorageRebuilder {
    /// Receiver for unpacked snapshot storage files
    file_receiver: Receiver<PathBuf>,
    /// Number of threads to rebuild with
    num_threads: usize,
    /// Snapshot storage lengths - from the snapshot file
    snapshot_storage_lengths: HashMap<Slot, HashMap<SerializedAccountsFileId, usize>>,
    /// Container for storing snapshot file paths
    storage_paths: DashMap<Slot, Mutex<Vec<PathBuf>>>,
    /// Container for storing rebuilt snapshot storages
    storage: AccountStorageMap,
    /// Tracks next append_vec_id
    next_append_vec_id: Arc<AtomicAccountsFileId>,
    /// Tracker for number of processed slots
    processed_slot_count: AtomicUsize,
    /// Tracks the number of collisions in AccountsFileId
    num_collisions: AtomicUsize,
    /// Rebuild from the snapshot files or archives
    snapshot_from: SnapshotFrom,
    /// specify how storages are accessed
    storage_access: StorageAccess,
}

impl SnapshotStorageRebuilder {
    /// Synchronously spawns threads to rebuild snapshot storages
    pub(crate) fn rebuild_storage(
        file_receiver: Receiver<PathBuf>,
        num_threads: usize,
        next_append_vec_id: Arc<AtomicAccountsFileId>,
        snapshot_from: SnapshotFrom,
        storage_access: StorageAccess,
    ) -> Result<RebuiltSnapshotStorage, SnapshotError> {
        let (snapshot_version_path, snapshot_file_path, append_vec_files) =
            Self::get_version_and_snapshot_files(&file_receiver);
        let snapshot_version_str = snapshot_version_from_file(snapshot_version_path)?;
        let snapshot_version = snapshot_version_str.parse().map_err(|err| {
            IoError::other(format!(
                "unsupported snapshot version '{snapshot_version_str}': {err}",
            ))
        })?;
        let snapshot_storage_lengths =
            Self::process_snapshot_file(snapshot_version, snapshot_file_path)?;

        let account_storage_map = Self::spawn_rebuilder_threads(
            file_receiver,
            num_threads,
            next_append_vec_id,
            snapshot_storage_lengths,
            append_vec_files,
            snapshot_from,
            storage_access,
        )?;

        Ok(RebuiltSnapshotStorage {
            snapshot_version,
            storage: account_storage_map,
        })
    }

    /// Create the SnapshotStorageRebuilder for storing state during rebuilding
    ///     - pre-allocates data for storage paths
    fn new(
        file_receiver: Receiver<PathBuf>,
        num_threads: usize,
        next_append_vec_id: Arc<AtomicAccountsFileId>,
        snapshot_storage_lengths: HashMap<Slot, HashMap<usize, usize>>,
        snapshot_from: SnapshotFrom,
        storage_access: StorageAccess,
    ) -> Self {
        let storage = DashMap::with_capacity(snapshot_storage_lengths.len());
        let storage_paths: DashMap<_, _> = snapshot_storage_lengths
            .iter()
            .map(|(slot, storage_lengths)| {
                (*slot, Mutex::new(Vec::with_capacity(storage_lengths.len())))
            })
            .collect();
        Self {
            file_receiver,
            num_threads,
            snapshot_storage_lengths,
            storage_paths,
            storage,
            next_append_vec_id,
            processed_slot_count: AtomicUsize::new(0),
            num_collisions: AtomicUsize::new(0),
            snapshot_from,
            storage_access,
        }
    }

    /// Waits for snapshot file
    /// Due to parallel unpacking, we may receive some append_vec files before the snapshot file
    /// This function will push append_vec files into a buffer until we receive the snapshot file
    fn get_version_and_snapshot_files(
        file_receiver: &Receiver<PathBuf>,
    ) -> (PathBuf, PathBuf, Vec<PathBuf>) {
        let mut append_vec_files = Vec::with_capacity(1024);
        let mut snapshot_version_path = None;
        let mut snapshot_file_path = None;

        loop {
            if let Ok(path) = file_receiver.recv() {
                let filename = path.file_name().unwrap().to_str().unwrap();
                match get_snapshot_file_kind(filename) {
                    Some(SnapshotFileKind::Version) => {
                        snapshot_version_path = Some(path);

                        // break if we have both the snapshot file and the version file
                        if snapshot_file_path.is_some() {
                            break;
                        }
                    }
                    Some(SnapshotFileKind::BankFields) => {
                        snapshot_file_path = Some(path);

                        // break if we have both the snapshot file and the version file
                        if snapshot_version_path.is_some() {
                            break;
                        }
                    }
                    Some(SnapshotFileKind::Storage) => {
                        append_vec_files.push(path);
                    }
                    None => {} // do nothing for other kinds of files
                }
            } else {
                panic!("did not receive snapshot file from unpacking threads");
            }
        }
        let snapshot_version_path = snapshot_version_path.unwrap();
        let snapshot_file_path = snapshot_file_path.unwrap();

        (snapshot_version_path, snapshot_file_path, append_vec_files)
    }

    /// Process the snapshot file to get the size of each snapshot storage file
    fn process_snapshot_file(
        snapshot_version: SnapshotVersion,
        snapshot_file_path: PathBuf,
    ) -> Result<HashMap<Slot, HashMap<usize, usize>>, bincode::Error> {
        let snapshot_file = File::open(snapshot_file_path).unwrap();
        let mut snapshot_stream = BufReader::new(snapshot_file);
        match snapshot_version {
            SnapshotVersion::V1_2_0 => {
                let (_bank_fields, accounts_fields) =
                    serde_snapshot::fields_from_stream(&mut snapshot_stream)?;

                Ok(snapshot_storage_lengths_from_fields(&accounts_fields))
            }
        }
    }

    /// Spawn threads for processing buffered append_vec_files, and then received files
    fn spawn_rebuilder_threads(
        file_receiver: Receiver<PathBuf>,
        num_threads: usize,
        next_append_vec_id: Arc<AtomicAccountsFileId>,
        snapshot_storage_lengths: HashMap<Slot, HashMap<usize, usize>>,
        append_vec_files: Vec<PathBuf>,
        snapshot_from: SnapshotFrom,
        storage_access: StorageAccess,
    ) -> Result<AccountStorageMap, SnapshotError> {
        let rebuilder = Arc::new(SnapshotStorageRebuilder::new(
            file_receiver,
            num_threads,
            next_append_vec_id,
            snapshot_storage_lengths,
            snapshot_from,
            storage_access,
        ));

        let thread_pool = rebuilder.build_thread_pool();

        if snapshot_from == SnapshotFrom::Archive {
            // Synchronously process buffered append_vec_files
            thread_pool.install(|| rebuilder.process_buffered_files(append_vec_files))?;
        }

        // Asynchronously spawn threads to process received append_vec_files
        let (exit_sender, exit_receiver) = unbounded();
        for _ in 0..rebuilder.num_threads {
            Self::spawn_receiver_thread(&thread_pool, exit_sender.clone(), rebuilder.clone());
        }
        drop(exit_sender); // drop otherwise loop below will never end

        // wait for asynchronous threads to complete
        rebuilder.wait_for_completion(exit_receiver)?;
        Ok(Arc::try_unwrap(rebuilder).unwrap().storage)
    }

    /// Processes buffered append_vec_files
    fn process_buffered_files(&self, append_vec_files: Vec<PathBuf>) -> Result<(), SnapshotError> {
        append_vec_files
            .into_par_iter()
            .map(|path| self.process_append_vec_file(path))
            .collect::<Result<(), SnapshotError>>()
    }

    /// Spawn a single thread to process received append_vec_files
    fn spawn_receiver_thread(
        thread_pool: &ThreadPool,
        exit_sender: Sender<Result<(), SnapshotError>>,
        rebuilder: Arc<SnapshotStorageRebuilder>,
    ) {
        thread_pool.spawn(move || {
            for path in rebuilder.file_receiver.iter() {
                match rebuilder.process_append_vec_file(path) {
                    Ok(_) => {}
                    Err(err) => {
                        exit_sender
                            .send(Err(err))
                            .expect("sender should be connected");
                        return;
                    }
                }
            }

            exit_sender
                .send(Ok(()))
                .expect("sender should be connected");
        })
    }

    /// Process an append_vec_file
    fn process_append_vec_file(&self, path: PathBuf) -> Result<(), SnapshotError> {
        let filename = path.file_name().unwrap().to_str().unwrap().to_owned();
        if let Ok((slot, append_vec_id)) = get_slot_and_append_vec_id(&filename) {
            if self.snapshot_from == SnapshotFrom::Dir {
                // Keep track of the highest append_vec_id in the system, so the future append_vecs
                // can be assigned to unique IDs.  This is only needed when loading from a snapshot
                // dir.  When loading from a snapshot archive, the max of the appendvec IDs is
                // updated in remap_append_vec_file(), which is not in the from_dir route.
                self.next_append_vec_id
                    .fetch_max((append_vec_id + 1) as AccountsFileId, Ordering::Relaxed);
            }
            let slot_storage_count = self.insert_storage_file(&slot, path);
            if slot_storage_count == self.snapshot_storage_lengths.get(&slot).unwrap().len() {
                // slot_complete
                self.process_complete_slot(slot)?;
                self.processed_slot_count.fetch_add(1, Ordering::AcqRel);
            }
        }
        Ok(())
    }

    /// Insert storage path into slot and return the number of storage files for the slot
    fn insert_storage_file(&self, slot: &Slot, path: PathBuf) -> usize {
        let slot_paths = self.storage_paths.get(slot).unwrap();
        let mut lock = slot_paths.lock().unwrap();
        lock.push(path);
        lock.len()
    }

    /// Process a slot that has received all storage entries
    fn process_complete_slot(&self, slot: Slot) -> Result<(), SnapshotError> {
        let slot_storage_paths = self.storage_paths.get(&slot).unwrap();
        let lock = slot_storage_paths.lock().unwrap();

        let slot_stores = lock
            .iter()
            .map(|path| {
                let filename = path.file_name().unwrap().to_str().unwrap();
                let (_, old_append_vec_id) = get_slot_and_append_vec_id(filename)?;
                let current_len = *self
                    .snapshot_storage_lengths
                    .get(&slot)
                    .unwrap()
                    .get(&old_append_vec_id)
                    .unwrap();

                let storage_entry = match &self.snapshot_from {
                    SnapshotFrom::Archive => remap_and_reconstruct_single_storage(
                        slot,
                        old_append_vec_id,
                        current_len,
                        path.as_path(),
                        &self.next_append_vec_id,
                        &self.num_collisions,
                        self.storage_access,
                    )?,
                    SnapshotFrom::Dir => reconstruct_single_storage(
                        &slot,
                        path.as_path(),
                        current_len,
                        old_append_vec_id as AccountsFileId,
                        self.storage_access,
                    )?,
                };

                Ok((storage_entry.append_vec_id(), storage_entry))
            })
            .collect::<Result<HashMap<AccountsFileId, Arc<AccountStorageEntry>>, SnapshotError>>(
            )?;

        if slot_stores.len() != 1 {
            return Err(SnapshotError::RebuildStorages(format!(
                "there must be exactly one storage per slot, but slot {slot} has {} storages",
                slot_stores.len()
            )));
        }
        // SAFETY: The check above guarantees there is one item in slot_stores,
        // so `.next()` will always return `Some`
        let (id, storage) = slot_stores.into_iter().next().unwrap();

        self.storage
            .insert(slot, AccountStorageReference { id, storage });
        Ok(())
    }

    /// Wait for the completion of the rebuilding threads
    fn wait_for_completion(
        &self,
        exit_receiver: Receiver<Result<(), SnapshotError>>,
    ) -> Result<(), SnapshotError> {
        let num_slots = self.snapshot_storage_lengths.len();
        let mut last_log_time = Instant::now();
        loop {
            select! {
                recv(exit_receiver) -> maybe_exit_signal => {
                    match maybe_exit_signal {
                        Ok(Ok(_)) => continue, // thread exited successfully
                        Ok(Err(err)) => { // thread exited with error
                            return Err(err);
                        }
                        Err(_) => break, // all threads have exited - channel disconnected
                    }
                }
                default(std::time::Duration::from_millis(100)) => {
                    let now = Instant::now();
                    if now.duration_since(last_log_time).as_millis() >= 2000 {
                        let num_processed_slots = self.processed_slot_count.load(Ordering::Relaxed);
                        let num_collisions = self.num_collisions.load(Ordering::Relaxed);
                        info!("rebuilt storages for {num_processed_slots}/{num_slots} slots with {num_collisions} collisions");
                        last_log_time = now;
                    }
                }
            }
        }

        Ok(())
    }

    /// Builds thread pool to rebuild with
    fn build_thread_pool(&self) -> ThreadPool {
        ThreadPoolBuilder::default()
            .thread_name(|i| format!("solRbuildSnap{i:02}"))
            .num_threads(self.num_threads)
            .build()
            .expect("new rayon threadpool")
    }
}

/// Used to determine if a filename is structured like a version file, bank file, or storage file
#[derive(PartialEq, Debug)]
enum SnapshotFileKind {
    Version,
    BankFields,
    Storage,
}

/// Determines `SnapshotFileKind` for `filename` if any
fn get_snapshot_file_kind(filename: &str) -> Option<SnapshotFileKind> {
    if VERSION_FILE_REGEX.is_match(filename) {
        Some(SnapshotFileKind::Version)
    } else if BANK_FIELDS_FILE_REGEX.is_match(filename) {
        Some(SnapshotFileKind::BankFields)
    } else if get_slot_and_append_vec_id(filename).is_ok() {
        Some(SnapshotFileKind::Storage)
    } else {
        None
    }
}

/// Get the slot and append vec id from the filename
pub(crate) fn get_slot_and_append_vec_id(filename: &str) -> Result<(Slot, usize), SnapshotError> {
    let mut parts = filename.splitn(2, '.');
    let slot = parts.next().and_then(|s| Slot::from_str(s).ok());
    let id = parts.next().and_then(|s| usize::from_str(s).ok());

    slot.zip(id)
        .ok_or_else(|| SnapshotError::InvalidAppendVecPath(PathBuf::from(filename)))
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::snapshot_utils::SNAPSHOT_VERSION_FILENAME,
        solana_accounts_db::accounts_file::AccountsFile,
    };

    #[test]
    fn test_get_snapshot_file_kind() {
        assert_eq!(None, get_snapshot_file_kind("file.txt"));
        assert_eq!(
            Some(SnapshotFileKind::Version),
            get_snapshot_file_kind(SNAPSHOT_VERSION_FILENAME)
        );
        assert_eq!(
            Some(SnapshotFileKind::BankFields),
            get_snapshot_file_kind("1234")
        );
        assert_eq!(
            Some(SnapshotFileKind::Storage),
            get_snapshot_file_kind("1000.999")
        );
    }

    #[test]
    fn test_get_slot_and_append_vec_id() {
        let expected_slot = 12345;
        let expected_id = 9987;
        let (slot, id) =
            get_slot_and_append_vec_id(&AccountsFile::file_name(expected_slot, expected_id))
                .unwrap();
        assert_eq!(expected_slot, slot);
        assert_eq!(expected_id as usize, id);
    }
}
