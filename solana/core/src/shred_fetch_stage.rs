//! The `shred_fetch_stage` pulls shreds from UDP sockets and sends it to a channel.

use {
    crate::repair::serve_repair::ServeRepair,
    bytes::Bytes,
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    itertools::Itertools,
    solana_gossip::cluster_info::ClusterInfo,
    solana_ledger::shred::{should_discard_shred, ShredFetchStats},
    solana_perf::packet::{PacketBatch, PacketBatchRecycler, PacketFlags, PACKETS_PER_BATCH},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        epoch_schedule::EpochSchedule,
        feature_set::{self, FeatureSet},
        genesis_config::ClusterType,
        packet::{Meta, PACKET_DATA_SIZE},
        pubkey::Pubkey,
    },
    solana_streamer::streamer::{self, PacketBatchReceiver, StreamerReceiveStats},
    std::{
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

const PACKET_COALESCE_DURATION: Duration = Duration::from_millis(1);

pub(crate) struct ShredFetchStage {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl ShredFetchStage {
    // updates packets received on a channel and sends them on another channel
    fn modify_packets(
        recvr: PacketBatchReceiver,
        sendr: Sender<PacketBatch>,
        bank_forks: &RwLock<BankForks>,
        shred_version: u16,
        name: &'static str,
        flags: PacketFlags,
        repair_context: Option<(&UdpSocket, &ClusterInfo)>,
        turbine_disabled: Arc<AtomicBool>,
    ) {
        const STATS_SUBMIT_CADENCE: Duration = Duration::from_secs(1);
        let mut last_updated = Instant::now();
        let mut keypair = repair_context
            .as_ref()
            .map(|(_, cluster_info)| cluster_info.keypair().clone());

        let (
            mut last_root,
            mut slots_per_epoch,
            mut feature_set,
            mut epoch_schedule,
            mut last_slot,
        ) = {
            let bank_forks_r = bank_forks.read().unwrap();
            let root_bank = bank_forks_r.root_bank();
            (
                root_bank.slot(),
                root_bank.get_slots_in_epoch(root_bank.epoch()),
                root_bank.feature_set.clone(),
                root_bank.epoch_schedule().clone(),
                bank_forks_r.highest_slot(),
            )
        };
        let mut stats = ShredFetchStats::default();
        let cluster_type = {
            let root_bank = bank_forks.read().unwrap().root_bank();
            root_bank.cluster_type()
        };

        for mut packet_batch in recvr {
            if last_updated.elapsed().as_millis() as u64 > DEFAULT_MS_PER_SLOT {
                last_updated = Instant::now();
                let root_bank = {
                    let bank_forks_r = bank_forks.read().unwrap();
                    last_slot = bank_forks_r.highest_slot();
                    bank_forks_r.root_bank()
                };
                feature_set = root_bank.feature_set.clone();
                epoch_schedule = root_bank.epoch_schedule().clone();
                last_root = root_bank.slot();
                slots_per_epoch = root_bank.get_slots_in_epoch(root_bank.epoch());
                keypair = repair_context
                    .as_ref()
                    .map(|(_, cluster_info)| cluster_info.keypair().clone());
            }
            stats.shred_count += packet_batch.len();

            if let Some((udp_socket, _)) = repair_context {
                debug_assert_eq!(flags, PacketFlags::REPAIR);
                debug_assert!(keypair.is_some());
                if let Some(ref keypair) = keypair {
                    ServeRepair::handle_repair_response_pings(
                        udp_socket,
                        keypair,
                        &mut packet_batch,
                        &mut stats,
                    );
                }
            }

            // Limit shreds to 2 epochs away.
            let max_slot = last_slot + 2 * slots_per_epoch;
            let enable_chained_merkle_shreds = |shred_slot| {
                cluster_type == ClusterType::Development
                    || check_feature_activation(
                        &feature_set::enable_chained_merkle_shreds::id(),
                        shred_slot,
                        &feature_set,
                        &epoch_schedule,
                    )
            };
            let turbine_disabled = turbine_disabled.load(Ordering::Relaxed);
            for packet in packet_batch.iter_mut().filter(|p| !p.meta().discard()) {
                if turbine_disabled
                    || should_discard_shred(
                        packet,
                        last_root,
                        max_slot,
                        shred_version,
                        enable_chained_merkle_shreds,
                        &mut stats,
                    )
                {
                    packet.meta_mut().set_discard(true);
                } else {
                    packet.meta_mut().flags.insert(flags);
                }
            }
            stats.maybe_submit(name, STATS_SUBMIT_CADENCE);
            if sendr.send(packet_batch).is_err() {
                break;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn packet_modifier(
        receiver_thread_name: &'static str,
        modifier_thread_name: &'static str,
        sockets: Vec<Arc<UdpSocket>>,
        exit: Arc<AtomicBool>,
        sender: Sender<PacketBatch>,
        recycler: PacketBatchRecycler,
        bank_forks: Arc<RwLock<BankForks>>,
        shred_version: u16,
        name: &'static str,
        flags: PacketFlags,
        repair_context: Option<(Arc<UdpSocket>, Arc<ClusterInfo>)>,
        turbine_disabled: Arc<AtomicBool>,
    ) -> (Vec<JoinHandle<()>>, JoinHandle<()>) {
        let (packet_sender, packet_receiver) = unbounded();
        let streamers = sockets
            .into_iter()
            .enumerate()
            .map(|(i, socket)| {
                streamer::receiver(
                    format!("{receiver_thread_name}{i:02}"),
                    socket,
                    exit.clone(),
                    packet_sender.clone(),
                    recycler.clone(),
                    Arc::new(StreamerReceiveStats::new("packet_modifier")),
                    PACKET_COALESCE_DURATION,
                    true, // use_pinned_memory
                    None, // in_vote_only_mode
                    false,
                )
            })
            .collect();
        let modifier_hdl = Builder::new()
            .name(modifier_thread_name.to_string())
            .spawn(move || {
                let repair_context = repair_context
                    .as_ref()
                    .map(|(socket, cluster_info)| (socket.as_ref(), cluster_info.as_ref()));
                Self::modify_packets(
                    packet_receiver,
                    sender,
                    &bank_forks,
                    shred_version,
                    name,
                    flags,
                    repair_context,
                    turbine_disabled,
                )
            })
            .unwrap();
        (streamers, modifier_hdl)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sockets: Vec<Arc<UdpSocket>>,
        turbine_quic_endpoint_receiver: Receiver<(Pubkey, SocketAddr, Bytes)>,
        repair_socket: Arc<UdpSocket>,
        repair_quic_endpoint_receiver: Receiver<(SocketAddr, Vec<u8>)>,
        sender: Sender<PacketBatch>,
        shred_version: u16,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
        turbine_disabled: Arc<AtomicBool>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let recycler = PacketBatchRecycler::warmed(100, 1024);

        let (mut tvu_threads, tvu_filter) = Self::packet_modifier(
            "solRcvrShred",
            "solTvuPktMod",
            sockets,
            exit.clone(),
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            shred_version,
            "shred_fetch",
            PacketFlags::empty(),
            None, // repair_context
            turbine_disabled.clone(),
        );

        let (repair_receiver, repair_handler) = Self::packet_modifier(
            "solRcvrShredRep",
            "solTvuRepPktMod",
            vec![repair_socket.clone()],
            exit.clone(),
            sender.clone(),
            recycler.clone(),
            bank_forks.clone(),
            shred_version,
            "shred_fetch_repair",
            PacketFlags::REPAIR,
            Some((repair_socket, cluster_info)),
            turbine_disabled.clone(),
        );

        tvu_threads.extend(repair_receiver);
        tvu_threads.push(tvu_filter);
        tvu_threads.push(repair_handler);
        // Repair shreds fetched over QUIC protocol.
        {
            let (packet_sender, packet_receiver) = unbounded();
            let bank_forks = bank_forks.clone();
            let recycler = recycler.clone();
            let exit = exit.clone();
            let sender = sender.clone();
            let turbine_disabled = turbine_disabled.clone();
            tvu_threads.extend([
                Builder::new()
                    .name("solTvuRecvRpr".to_string())
                    .spawn(|| {
                        receive_repair_quic_packets(
                            repair_quic_endpoint_receiver,
                            packet_sender,
                            recycler,
                            exit,
                        )
                    })
                    .unwrap(),
                Builder::new()
                    .name("solTvuFetchRpr".to_string())
                    .spawn(move || {
                        Self::modify_packets(
                            packet_receiver,
                            sender,
                            &bank_forks,
                            shred_version,
                            "shred_fetch_repair_quic",
                            PacketFlags::REPAIR,
                            None, // repair_context; no ping packets!
                            turbine_disabled,
                        )
                    })
                    .unwrap(),
            ]);
        }
        // Turbine shreds fetched over QUIC protocol.
        let (packet_sender, packet_receiver) = unbounded();
        tvu_threads.extend([
            Builder::new()
                .name("solTvuRecvQuic".to_string())
                .spawn(|| {
                    receive_quic_datagrams(
                        turbine_quic_endpoint_receiver,
                        packet_sender,
                        recycler,
                        exit,
                    )
                })
                .unwrap(),
            Builder::new()
                .name("solTvuFetchQuic".to_string())
                .spawn(move || {
                    Self::modify_packets(
                        packet_receiver,
                        sender,
                        &bank_forks,
                        shred_version,
                        "shred_fetch_quic",
                        PacketFlags::empty(),
                        None, // repair_context
                        turbine_disabled,
                    )
                })
                .unwrap(),
        ]);
        Self {
            thread_hdls: tvu_threads,
        }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}

fn receive_quic_datagrams(
    turbine_quic_endpoint_receiver: Receiver<(Pubkey, SocketAddr, Bytes)>,
    sender: Sender<PacketBatch>,
    recycler: PacketBatchRecycler,
    exit: Arc<AtomicBool>,
) {
    const RECV_TIMEOUT: Duration = Duration::from_secs(1);
    while !exit.load(Ordering::Relaxed) {
        let entry = match turbine_quic_endpoint_receiver.recv_timeout(RECV_TIMEOUT) {
            Ok(entry) => entry,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let mut packet_batch =
            PacketBatch::new_with_recycler(&recycler, PACKETS_PER_BATCH, "receive_quic_datagrams");
        unsafe {
            packet_batch.set_len(PACKETS_PER_BATCH);
        };
        let deadline = Instant::now() + PACKET_COALESCE_DURATION;
        let entries = std::iter::once(entry).chain(
            std::iter::repeat_with(|| turbine_quic_endpoint_receiver.recv_deadline(deadline).ok())
                .while_some(),
        );
        let size = entries
            .filter(|(_, _, bytes)| bytes.len() <= PACKET_DATA_SIZE)
            .zip(packet_batch.iter_mut())
            .map(|((_pubkey, addr, bytes), packet)| {
                *packet.meta_mut() = Meta {
                    size: bytes.len(),
                    addr: addr.ip(),
                    port: addr.port(),
                    flags: PacketFlags::empty(),
                };
                packet.buffer_mut()[..bytes.len()].copy_from_slice(&bytes);
            })
            .count();
        if size > 0 {
            packet_batch.truncate(size);
            if sender.send(packet_batch).is_err() {
                return;
            }
        }
    }
}

pub(crate) fn receive_repair_quic_packets(
    repair_quic_endpoint_receiver: Receiver<(SocketAddr, Vec<u8>)>,
    sender: Sender<PacketBatch>,
    recycler: PacketBatchRecycler,
    exit: Arc<AtomicBool>,
) {
    const RECV_TIMEOUT: Duration = Duration::from_secs(1);
    while !exit.load(Ordering::Relaxed) {
        let entry = match repair_quic_endpoint_receiver.recv_timeout(RECV_TIMEOUT) {
            Ok(entry) => entry,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let mut packet_batch =
            PacketBatch::new_with_recycler(&recycler, PACKETS_PER_BATCH, "receive_quic_datagrams");
        unsafe {
            packet_batch.set_len(PACKETS_PER_BATCH);
        };
        let deadline = Instant::now() + PACKET_COALESCE_DURATION;
        let entries = std::iter::once(entry).chain(
            std::iter::repeat_with(|| repair_quic_endpoint_receiver.recv_deadline(deadline).ok())
                .while_some(),
        );
        let size = entries
            .filter(|(_, bytes)| bytes.len() <= PACKET_DATA_SIZE)
            .zip(packet_batch.iter_mut())
            .map(|((addr, bytes), packet)| {
                *packet.meta_mut() = Meta {
                    size: bytes.len(),
                    addr: addr.ip(),
                    port: addr.port(),
                    flags: PacketFlags::REPAIR,
                };
                packet.buffer_mut()[..bytes.len()].copy_from_slice(&bytes);
            })
            .count();
        if size > 0 {
            packet_batch.truncate(size);
            if sender.send(packet_batch).is_err() {
                return; // The receiver end of the channel is disconnected.
            }
        }
    }
}

// Returns true if the feature is effective for the shred slot.
#[must_use]
fn check_feature_activation(
    feature: &Pubkey,
    shred_slot: Slot,
    feature_set: &FeatureSet,
    epoch_schedule: &EpochSchedule,
) -> bool {
    match feature_set.activated_slot(feature) {
        None => false,
        Some(feature_slot) => {
            let feature_epoch = epoch_schedule.get_epoch(feature_slot);
            let shred_epoch = epoch_schedule.get_epoch(shred_slot);
            feature_epoch < shred_epoch
        }
    }
}
