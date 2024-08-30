//! `window_service` handles the data plane incoming shreds, storing them in
//!   blockstore and retransmitting where required
//!

use {
    crate::{
        cluster_info_vote_listener::VerifiedVoteReceiver,
        completed_data_sets_service::CompletedDataSetsSender,
        repair::{
            ancestor_hashes_service::AncestorHashesReplayUpdateReceiver,
            quic_endpoint::LocalRequest,
            repair_response,
            repair_service::{
                DumpedSlotsReceiver, OutstandingShredRepairs, PopularPrunedForksSender, RepairInfo,
                RepairService,
            },
        },
        result::{Error, Result},
    },
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    rayon::{prelude::*, ThreadPool},
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::{
        blockstore::{Blockstore, BlockstoreInsertionMetrics, PossibleDuplicateShred},
        leader_schedule_cache::LeaderScheduleCache,
        shred::{self, Nonce, ReedSolomonCache, Shred},
    },
    solana_measure::measure::Measure,
    solana_metrics::inc_new_counter_error,
    solana_perf::packet::{Packet, PacketBatch},
    solana_rayon_threadlimit::get_thread_count,
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        feature_set,
    },
    solana_turbine::cluster_nodes,
    std::{
        cmp::Reverse,
        collections::{HashMap, HashSet},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::mpsc::Sender as AsyncSender,
};

type ShredPayload = Vec<u8>;
type DuplicateSlotSender = Sender<Slot>;
pub(crate) type DuplicateSlotReceiver = Receiver<Slot>;

#[derive(Default)]
struct WindowServiceMetrics {
    run_insert_count: u64,
    num_packets: usize,
    num_repairs: usize,
    num_shreds_received: usize,
    handle_packets_elapsed_us: u64,
    shred_receiver_elapsed_us: u64,
    prune_shreds_elapsed_us: u64,
    num_shreds_pruned_invalid_repair: usize,
    num_errors: u64,
    num_errors_blockstore: u64,
    num_errors_cross_beam_recv_timeout: u64,
    num_errors_other: u64,
    num_errors_try_crossbeam_send: u64,
    addrs: HashMap</*source:*/ SocketAddr, /*num packets:*/ usize>,
}

impl WindowServiceMetrics {
    fn report_metrics(&self, metric_name: &'static str) {
        const MAX_NUM_ADDRS: usize = 5;
        datapoint_info!(
            metric_name,
            (
                "handle_packets_elapsed_us",
                self.handle_packets_elapsed_us,
                i64
            ),
            ("run_insert_count", self.run_insert_count as i64, i64),
            ("num_packets", self.num_packets, i64),
            ("num_repairs", self.num_repairs, i64),
            ("num_shreds_received", self.num_shreds_received, i64),
            (
                "shred_receiver_elapsed_us",
                self.shred_receiver_elapsed_us as i64,
                i64
            ),
            (
                "prune_shreds_elapsed_us",
                self.prune_shreds_elapsed_us as i64,
                i64
            ),
            (
                "num_shreds_pruned_invalid_repair",
                self.num_shreds_pruned_invalid_repair,
                i64
            ),
            ("num_errors", self.num_errors, i64),
            ("num_errors_blockstore", self.num_errors_blockstore, i64),
            ("num_errors_other", self.num_errors_other, i64),
            (
                "num_errors_try_crossbeam_send",
                self.num_errors_try_crossbeam_send,
                i64
            ),
            (
                "num_errors_cross_beam_recv_timeout",
                self.num_errors_cross_beam_recv_timeout,
                i64
            ),
        );

        let mut addrs: Vec<_> = self.addrs.iter().collect();
        let reverse_count = |(_addr, count): &_| Reverse(*count);
        if addrs.len() > MAX_NUM_ADDRS {
            addrs.select_nth_unstable_by_key(MAX_NUM_ADDRS, reverse_count);
            addrs.truncate(MAX_NUM_ADDRS);
        }
        addrs.sort_unstable_by_key(reverse_count);
        info!(
            "num addresses: {}, top packets by source: {:?}",
            self.addrs.len(),
            addrs
        );
    }

    fn record_error(&mut self, err: &Error) {
        self.num_errors += 1;
        match err {
            Error::TrySend => self.num_errors_try_crossbeam_send += 1,
            Error::RecvTimeout(_) => self.num_errors_cross_beam_recv_timeout += 1,
            Error::Blockstore(err) => {
                self.num_errors_blockstore += 1;
                error!("blockstore error: {}", err);
            }
            _ => self.num_errors_other += 1,
        }
    }
}

fn run_check_duplicate(
    cluster_info: &ClusterInfo,
    blockstore: &Blockstore,
    shred_receiver: &Receiver<PossibleDuplicateShred>,
    duplicate_slots_sender: &DuplicateSlotSender,
    bank_forks: &RwLock<BankForks>,
) -> Result<()> {
    let mut root_bank = bank_forks.read().unwrap().root_bank();
    let mut last_updated = Instant::now();
    let check_duplicate = |shred: PossibleDuplicateShred| -> Result<()> {
        if last_updated.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
            // Grabs bank forks lock once a slot
            last_updated = Instant::now();
            root_bank = bank_forks.read().unwrap().root_bank();
        }
        let shred_slot = shred.slot();
        let merkle_conflict_duplicate_proofs = cluster_nodes::check_feature_activation(
            &feature_set::merkle_conflict_duplicate_proofs::id(),
            shred_slot,
            &root_bank,
        );
        let chained_merkle_conflict_duplicate_proofs = cluster_nodes::check_feature_activation(
            &feature_set::chained_merkle_conflict_duplicate_proofs::id(),
            shred_slot,
            &root_bank,
        );
        let (shred1, shred2) = match shred {
            PossibleDuplicateShred::LastIndexConflict(shred, conflict)
            | PossibleDuplicateShred::ErasureConflict(shred, conflict) => (shred, conflict),
            PossibleDuplicateShred::MerkleRootConflict(shred, conflict) => {
                if merkle_conflict_duplicate_proofs {
                    // Although this proof can be immediately stored on detection, we wait until
                    // here in order to check the feature flag, as storage in blockstore can
                    // preclude the detection of other duplicate proofs in this slot
                    if blockstore.has_duplicate_shreds_in_slot(shred_slot) {
                        return Ok(());
                    }
                    blockstore.store_duplicate_slot(
                        shred_slot,
                        conflict.clone(),
                        shred.clone().into_payload(),
                    )?;
                    (shred, conflict)
                } else {
                    return Ok(());
                }
            }
            PossibleDuplicateShred::ChainedMerkleRootConflict(shred, conflict) => {
                if chained_merkle_conflict_duplicate_proofs {
                    // Although this proof can be immediately stored on detection, we wait until
                    // here in order to check the feature flag, as storage in blockstore can
                    // preclude the detection of other duplicate proofs in this slot
                    if blockstore.has_duplicate_shreds_in_slot(shred_slot) {
                        return Ok(());
                    }
                    blockstore.store_duplicate_slot(
                        shred_slot,
                        conflict.clone(),
                        shred.clone().into_payload(),
                    )?;
                    (shred, conflict)
                } else {
                    return Ok(());
                }
            }
            PossibleDuplicateShred::Exists(shred) => {
                // Unlike the other cases we have to wait until here to decide to handle the duplicate and store
                // in blockstore. This is because the duplicate could have been part of the same insert batch,
                // so we wait until the batch has been written.
                if blockstore.has_duplicate_shreds_in_slot(shred_slot) {
                    return Ok(()); // A duplicate is already recorded
                }
                let Some(existing_shred_payload) = blockstore.is_shred_duplicate(&shred) else {
                    return Ok(()); // Not a duplicate
                };
                blockstore.store_duplicate_slot(
                    shred_slot,
                    existing_shred_payload.clone(),
                    shred.clone().into_payload(),
                )?;
                (shred, existing_shred_payload)
            }
        };

        // Propagate duplicate proof through gossip
        cluster_info.push_duplicate_shred(&shred1, &shred2)?;
        // Notify duplicate consensus state machine
        duplicate_slots_sender.send(shred_slot)?;

        Ok(())
    };
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);
    std::iter::once(shred_receiver.recv_timeout(RECV_TIMEOUT)?)
        .chain(shred_receiver.try_iter())
        .try_for_each(check_duplicate)
}

fn verify_repair(
    outstanding_requests: &mut OutstandingShredRepairs,
    shred: &Shred,
    repair_meta: &Option<RepairMeta>,
) -> bool {
    repair_meta
        .as_ref()
        .map(|repair_meta| {
            outstanding_requests
                .register_response(
                    repair_meta.nonce,
                    shred,
                    solana_sdk::timing::timestamp(),
                    |_| (),
                )
                .is_some()
        })
        .unwrap_or(true)
}

fn prune_shreds_by_repair_status(
    shreds: &mut Vec<Shred>,
    repair_infos: &mut Vec<Option<RepairMeta>>,
    outstanding_requests: &RwLock<OutstandingShredRepairs>,
    accept_repairs_only: bool,
) {
    assert_eq!(shreds.len(), repair_infos.len());
    let mut i = 0;
    let mut removed = HashSet::new();
    {
        let mut outstanding_requests = outstanding_requests.write().unwrap();
        shreds.retain(|shred| {
            let should_keep = (
                (!accept_repairs_only || repair_infos[i].is_some())
                    && verify_repair(&mut outstanding_requests, shred, &repair_infos[i]),
                i += 1,
            )
                .0;
            if !should_keep {
                removed.insert(i - 1);
            }
            should_keep
        });
    }
    i = 0;
    repair_infos.retain(|_repair_info| (!removed.contains(&i), i += 1).0);
    assert_eq!(shreds.len(), repair_infos.len());
}

#[allow(clippy::too_many_arguments)]
fn run_insert<F>(
    thread_pool: &ThreadPool,
    verified_receiver: &Receiver<Vec<PacketBatch>>,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    handle_duplicate: F,
    metrics: &mut BlockstoreInsertionMetrics,
    ws_metrics: &mut WindowServiceMetrics,
    completed_data_sets_sender: Option<&CompletedDataSetsSender>,
    retransmit_sender: &Sender<Vec<ShredPayload>>,
    outstanding_requests: &RwLock<OutstandingShredRepairs>,
    reed_solomon_cache: &ReedSolomonCache,
    accept_repairs_only: bool,
) -> Result<()>
where
    F: Fn(PossibleDuplicateShred),
{
    const RECV_TIMEOUT: Duration = Duration::from_millis(200);
    let mut shred_receiver_elapsed = Measure::start("shred_receiver_elapsed");
    let mut packets = verified_receiver.recv_timeout(RECV_TIMEOUT)?;
    packets.extend(verified_receiver.try_iter().flatten());
    shred_receiver_elapsed.stop();
    ws_metrics.shred_receiver_elapsed_us += shred_receiver_elapsed.as_us();
    ws_metrics.run_insert_count += 1;
    let handle_packet = |packet: &Packet| {
        if packet.meta().discard() {
            return None;
        }
        let shred = shred::layout::get_shred(packet)?;
        let shred = Shred::new_from_serialized_shred(shred.to_vec()).ok()?;
        if packet.meta().repair() {
            let repair_info = RepairMeta {
                // If can't parse the nonce, dump the packet.
                nonce: repair_response::nonce(packet)?,
            };
            Some((shred, Some(repair_info)))
        } else {
            Some((shred, None))
        }
    };
    let now = Instant::now();
    let (mut shreds, mut repair_infos): (Vec<_>, Vec<_>) = thread_pool.install(|| {
        packets
            .par_iter()
            .flat_map_iter(|packets| packets.iter().filter_map(handle_packet))
            .unzip()
    });
    ws_metrics.handle_packets_elapsed_us += now.elapsed().as_micros() as u64;
    ws_metrics.num_packets += packets.iter().map(PacketBatch::len).sum::<usize>();
    ws_metrics.num_repairs += repair_infos.iter().filter(|r| r.is_some()).count();
    ws_metrics.num_shreds_received += shreds.len();
    for packet in packets.iter().flat_map(PacketBatch::iter) {
        let addr = packet.meta().socket_addr();
        *ws_metrics.addrs.entry(addr).or_default() += 1;
    }

    let mut prune_shreds_elapsed = Measure::start("prune_shreds_elapsed");
    let num_shreds = shreds.len();
    prune_shreds_by_repair_status(
        &mut shreds,
        &mut repair_infos,
        outstanding_requests,
        accept_repairs_only,
    );
    ws_metrics.num_shreds_pruned_invalid_repair = num_shreds - shreds.len();
    let repairs: Vec<_> = repair_infos
        .iter()
        .map(|repair_info| repair_info.is_some())
        .collect();
    prune_shreds_elapsed.stop();
    ws_metrics.prune_shreds_elapsed_us += prune_shreds_elapsed.as_us();

    let completed_data_sets = blockstore.insert_shreds_handle_duplicate(
        shreds,
        repairs,
        Some(leader_schedule_cache),
        false, // is_trusted
        Some(retransmit_sender),
        &handle_duplicate,
        reed_solomon_cache,
        metrics,
    )?;

    if let Some(sender) = completed_data_sets_sender {
        sender.try_send(completed_data_sets)?;
    }

    Ok(())
}

struct RepairMeta {
    nonce: Nonce,
}

pub(crate) struct WindowService {
    t_insert: JoinHandle<()>,
    t_check_duplicate: JoinHandle<()>,
    repair_service: RepairService,
}

impl WindowService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        blockstore: Arc<Blockstore>,
        verified_receiver: Receiver<Vec<PacketBatch>>,
        retransmit_sender: Sender<Vec<ShredPayload>>,
        repair_socket: Arc<UdpSocket>,
        ancestor_hashes_socket: Arc<UdpSocket>,
        repair_quic_endpoint_sender: AsyncSender<LocalRequest>,
        repair_quic_endpoint_response_sender: Sender<(SocketAddr, Vec<u8>)>,
        exit: Arc<AtomicBool>,
        repair_info: RepairInfo,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        verified_vote_receiver: VerifiedVoteReceiver,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        duplicate_slots_sender: DuplicateSlotSender,
        ancestor_hashes_replay_update_receiver: AncestorHashesReplayUpdateReceiver,
        dumped_slots_receiver: DumpedSlotsReceiver,
        popular_pruned_forks_sender: PopularPrunedForksSender,
        outstanding_repair_requests: Arc<RwLock<OutstandingShredRepairs>>,
    ) -> WindowService {
        let cluster_info = repair_info.cluster_info.clone();
        let bank_forks = repair_info.bank_forks.clone();

        // In wen_restart, we discard all shreds from Turbine and keep only those from repair to
        // avoid new shreds make validator OOM before wen_restart is over.
        let accept_repairs_only = repair_info.wen_restart_repair_slots.is_some();

        let repair_service = RepairService::new(
            blockstore.clone(),
            exit.clone(),
            repair_socket,
            ancestor_hashes_socket,
            repair_quic_endpoint_sender,
            repair_quic_endpoint_response_sender,
            repair_info,
            verified_vote_receiver,
            outstanding_repair_requests.clone(),
            ancestor_hashes_replay_update_receiver,
            dumped_slots_receiver,
            popular_pruned_forks_sender,
        );

        let (duplicate_sender, duplicate_receiver) = unbounded();

        let t_check_duplicate = Self::start_check_duplicate_thread(
            cluster_info,
            exit.clone(),
            blockstore.clone(),
            duplicate_receiver,
            duplicate_slots_sender,
            bank_forks,
        );

        let t_insert = Self::start_window_insert_thread(
            exit,
            blockstore,
            leader_schedule_cache,
            verified_receiver,
            duplicate_sender,
            completed_data_sets_sender,
            retransmit_sender,
            outstanding_repair_requests,
            accept_repairs_only,
        );

        WindowService {
            t_insert,
            t_check_duplicate,
            repair_service,
        }
    }

    fn start_check_duplicate_thread(
        cluster_info: Arc<ClusterInfo>,
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        duplicate_receiver: Receiver<PossibleDuplicateShred>,
        duplicate_slots_sender: DuplicateSlotSender,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> JoinHandle<()> {
        let handle_error = || {
            inc_new_counter_error!("solana-check-duplicate-error", 1, 1);
        };
        Builder::new()
            .name("solWinCheckDup".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    if let Err(e) = run_check_duplicate(
                        &cluster_info,
                        &blockstore,
                        &duplicate_receiver,
                        &duplicate_slots_sender,
                        &bank_forks,
                    ) {
                        if Self::should_exit_on_error(e, &handle_error) {
                            break;
                        }
                    }
                }
            })
            .unwrap()
    }

    fn start_window_insert_thread(
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        verified_receiver: Receiver<Vec<PacketBatch>>,
        check_duplicate_sender: Sender<PossibleDuplicateShred>,
        completed_data_sets_sender: Option<CompletedDataSetsSender>,
        retransmit_sender: Sender<Vec<ShredPayload>>,
        outstanding_requests: Arc<RwLock<OutstandingShredRepairs>>,
        accept_repairs_only: bool,
    ) -> JoinHandle<()> {
        let handle_error = || {
            inc_new_counter_error!("solana-window-insert-error", 1, 1);
        };
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(get_thread_count().min(8))
            .thread_name(|i| format!("solWinInsert{i:02}"))
            .build()
            .unwrap();
        let reed_solomon_cache = ReedSolomonCache::default();
        Builder::new()
            .name("solWinInsert".to_string())
            .spawn(move || {
                let handle_duplicate = |possible_duplicate_shred| {
                    let _ = check_duplicate_sender.send(possible_duplicate_shred);
                };
                let mut metrics = BlockstoreInsertionMetrics::default();
                let mut ws_metrics = WindowServiceMetrics::default();
                let mut last_print = Instant::now();
                while !exit.load(Ordering::Relaxed) {
                    if let Err(e) = run_insert(
                        &thread_pool,
                        &verified_receiver,
                        &blockstore,
                        &leader_schedule_cache,
                        handle_duplicate,
                        &mut metrics,
                        &mut ws_metrics,
                        completed_data_sets_sender.as_ref(),
                        &retransmit_sender,
                        &outstanding_requests,
                        &reed_solomon_cache,
                        accept_repairs_only,
                    ) {
                        ws_metrics.record_error(&e);
                        if Self::should_exit_on_error(e, &handle_error) {
                            break;
                        }
                    }

                    if last_print.elapsed().as_secs() > 2 {
                        metrics.report_metrics("blockstore-insert-shreds");
                        metrics = BlockstoreInsertionMetrics::default();
                        ws_metrics.report_metrics("recv-window-insert-shreds");
                        ws_metrics = WindowServiceMetrics::default();
                        last_print = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    fn should_exit_on_error<H>(e: Error, handle_error: &H) -> bool
    where
        H: Fn(),
    {
        match e {
            Error::RecvTimeout(RecvTimeoutError::Disconnected) => true,
            Error::RecvTimeout(RecvTimeoutError::Timeout) => false,
            Error::Send => true,
            _ => {
                handle_error();
                error!("thread {:?} error {:?}", thread::current().name(), e);
                false
            }
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.t_insert.join()?;
        self.t_check_duplicate.join()?;
        self.repair_service.join()
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::repair::serve_repair::ShredRepairType,
        rand::Rng,
        solana_entry::entry::{create_ticks, Entry},
        solana_gossip::contact_info::ContactInfo,
        solana_ledger::{
            blockstore::{make_many_slot_entries, Blockstore},
            genesis_utils::create_genesis_config,
            get_tmp_ledger_path_auto_delete,
            shred::{ProcessShredsStats, Shredder},
        },
        solana_runtime::bank::Bank,
        solana_sdk::{
            hash::Hash,
            signature::{Keypair, Signer},
            timing::timestamp,
        },
        solana_streamer::socket::SocketAddrSpace,
    };

    fn local_entries_to_shred(
        entries: &[Entry],
        slot: Slot,
        parent: Slot,
        keypair: &Keypair,
    ) -> Vec<Shred> {
        let shredder = Shredder::new(slot, parent, 0, 0).unwrap();
        let (data_shreds, _) = shredder.entries_to_shreds(
            keypair,
            entries,
            true, // is_last_in_slot
            // chained_merkle_root
            Some(Hash::new_from_array(rand::thread_rng().gen())),
            0,    // next_shred_index
            0,    // next_code_index
            true, // merkle_variant
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        );
        data_shreds
    }

    #[test]
    fn test_process_shred() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let num_entries = 10;
        let original_entries = create_ticks(num_entries, 0, Hash::default());
        let mut shreds = local_entries_to_shred(&original_entries, 0, 0, &Keypair::new());
        shreds.reverse();
        blockstore
            .insert_shreds(shreds, None, false)
            .expect("Expect successful processing of shred");

        assert_eq!(blockstore.get_slot_entries(0, 0).unwrap(), original_entries);
    }

    #[test]
    fn test_run_check_duplicate() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let (sender, receiver) = unbounded();
        let (duplicate_slot_sender, duplicate_slot_receiver) = unbounded();
        let (shreds, _) = make_many_slot_entries(5, 5, 10);
        blockstore
            .insert_shreds(shreds.clone(), None, false)
            .unwrap();
        let duplicate_index = 0;
        let original_shred = shreds[duplicate_index].clone();
        let duplicate_shred = {
            let (mut shreds, _) = make_many_slot_entries(5, 1, 10);
            shreds.swap_remove(duplicate_index)
        };
        assert_eq!(duplicate_shred.slot(), shreds[0].slot());
        let duplicate_shred_slot = duplicate_shred.slot();
        sender
            .send(PossibleDuplicateShred::Exists(duplicate_shred.clone()))
            .unwrap();
        assert!(!blockstore.has_duplicate_shreds_in_slot(duplicate_shred_slot));
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), timestamp());
        let cluster_info = ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        );
        run_check_duplicate(
            &cluster_info,
            &blockstore,
            &receiver,
            &duplicate_slot_sender,
            &bank_forks,
        )
        .unwrap();

        // Make sure the correct duplicate proof was stored
        let duplicate_proof = blockstore.get_duplicate_slot(duplicate_shred_slot).unwrap();
        assert_eq!(duplicate_proof.shred1, *original_shred.payload());
        assert_eq!(duplicate_proof.shred2, *duplicate_shred.payload());

        // Make sure a duplicate signal was sent
        assert_eq!(
            duplicate_slot_receiver.try_recv().unwrap(),
            duplicate_shred_slot
        );
    }

    #[test]
    fn test_store_duplicate_shreds_same_batch() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let (duplicate_shred_sender, duplicate_shred_receiver) = unbounded();
        let (duplicate_slot_sender, duplicate_slot_receiver) = unbounded();
        let exit = Arc::new(AtomicBool::new(false));
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), timestamp());
        let cluster_info = Arc::new(ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        ));
        let genesis_config = create_genesis_config(10_000).genesis_config;
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));

        // Start duplicate thread receiving and inserting duplicates
        let t_check_duplicate = WindowService::start_check_duplicate_thread(
            cluster_info,
            exit.clone(),
            blockstore.clone(),
            duplicate_shred_receiver,
            duplicate_slot_sender,
            bank_forks,
        );

        let handle_duplicate = |shred| {
            let _ = duplicate_shred_sender.send(shred);
        };
        let num_trials = 100;
        for slot in 0..num_trials {
            let (shreds, _) = make_many_slot_entries(slot, 1, 10);
            let duplicate_index = 0;
            let original_shred = shreds[duplicate_index].clone();
            let duplicate_shred = {
                let (mut shreds, _) = make_many_slot_entries(slot, 1, 10);
                shreds.swap_remove(duplicate_index)
            };
            assert_eq!(duplicate_shred.slot(), slot);
            // Simulate storing both duplicate shreds in the same batch
            blockstore
                .insert_shreds_handle_duplicate(
                    vec![original_shred.clone(), duplicate_shred.clone()],
                    vec![false, false],
                    None,
                    false, // is_trusted
                    None,
                    &handle_duplicate,
                    &ReedSolomonCache::default(),
                    &mut BlockstoreInsertionMetrics::default(),
                )
                .unwrap();

            // Make sure a duplicate signal was sent
            assert_eq!(
                duplicate_slot_receiver
                    .recv_timeout(Duration::from_millis(5_000))
                    .unwrap(),
                slot
            );

            // Make sure the correct duplicate proof was stored
            let duplicate_proof = blockstore.get_duplicate_slot(slot).unwrap();
            assert_eq!(duplicate_proof.shred1, *original_shred.payload());
            assert_eq!(duplicate_proof.shred2, *duplicate_shred.payload());
        }
        exit.store(true, Ordering::Relaxed);
        t_check_duplicate.join().unwrap();
    }

    #[test]
    fn test_prune_shreds() {
        solana_logger::setup();
        let shred = Shred::new_from_parity_shard(
            5,   // slot
            5,   // index
            &[], // parity_shard
            5,   // fec_set_index
            6,   // num_data_shreds
            6,   // num_coding_shreds
            4,   // position
            0,   // version
        );
        let mut shreds = vec![shred.clone(), shred.clone(), shred.clone()];
        let repair_meta = RepairMeta { nonce: 0 };
        let outstanding_requests = Arc::new(RwLock::new(OutstandingShredRepairs::default()));
        let repair_type = ShredRepairType::Orphan(9);
        let nonce = outstanding_requests
            .write()
            .unwrap()
            .add_request(repair_type, timestamp());
        let repair_meta1 = RepairMeta { nonce };
        let mut repair_infos = vec![None, Some(repair_meta), Some(repair_meta1)];
        prune_shreds_by_repair_status(&mut shreds, &mut repair_infos, &outstanding_requests, false);
        assert_eq!(shreds.len(), 2);
        assert_eq!(repair_infos.len(), 2);
        assert!(repair_infos[0].is_none());
        assert_eq!(repair_infos[1].as_ref().unwrap().nonce, nonce);

        shreds = vec![shred.clone(), shred.clone(), shred];
        let repair_meta2 = RepairMeta { nonce: 0 };
        let repair_meta3 = RepairMeta { nonce };
        repair_infos = vec![None, Some(repair_meta2), Some(repair_meta3)];
        // In wen_restart, we discard all Turbine shreds and only keep valid repair shreds.
        prune_shreds_by_repair_status(&mut shreds, &mut repair_infos, &outstanding_requests, true);
        assert_eq!(shreds.len(), 1);
        assert_eq!(repair_infos.len(), 1);
        assert!(repair_infos[0].is_some());
        assert_eq!(repair_infos[0].as_ref().unwrap().nonce, nonce);
    }
}
