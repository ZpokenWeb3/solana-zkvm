mod snapshot_gossip_manager;
use {
    crossbeam_channel::{Receiver, Sender},
    snapshot_gossip_manager::SnapshotGossipManager,
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::{measure::Measure, measure_us},
    solana_perf::thread::renice_this_thread,
    solana_runtime::{
        snapshot_config::SnapshotConfig,
        snapshot_hash::StartingSnapshotHashes,
        snapshot_package::{self, SnapshotPackage},
        snapshot_utils,
    },
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct SnapshotPackagerService {
    t_snapshot_packager: JoinHandle<()>,
}

impl SnapshotPackagerService {
    /// If there are no snapshot packages to handle, limit how often we re-check
    const LOOP_LIMITER: Duration = Duration::from_millis(100);

    pub fn new(
        snapshot_package_sender: Sender<SnapshotPackage>,
        snapshot_package_receiver: Receiver<SnapshotPackage>,
        starting_snapshot_hashes: Option<StartingSnapshotHashes>,
        exit: Arc<AtomicBool>,
        cluster_info: Arc<ClusterInfo>,
        snapshot_config: SnapshotConfig,
        enable_gossip_push: bool,
    ) -> Self {
        let t_snapshot_packager = Builder::new()
            .name("solSnapshotPkgr".to_string())
            .spawn(move || {
                info!("SnapshotPackagerService has started");
                renice_this_thread(snapshot_config.packager_thread_niceness_adj).unwrap();
                let mut snapshot_gossip_manager = enable_gossip_push
                    .then(|| SnapshotGossipManager::new(cluster_info, starting_snapshot_hashes));

                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some((
                        snapshot_package,
                        num_outstanding_snapshot_packages,
                        num_re_enqueued_snapshot_packages,
                    )) = Self::get_next_snapshot_package(
                        &snapshot_package_sender,
                        &snapshot_package_receiver,
                    )
                    else {
                        std::thread::sleep(Self::LOOP_LIMITER);
                        continue;
                    };
                    info!("handling snapshot package: {snapshot_package:?}");
                    let enqueued_time = snapshot_package.enqueued.elapsed();

                    let measure_handling = Measure::start("");
                    let snapshot_kind = snapshot_package.snapshot_kind;
                    let snapshot_slot = snapshot_package.slot;
                    let snapshot_hash = snapshot_package.hash;

                    // Archiving the snapshot package is not allowed to fail.
                    // AccountsBackgroundService calls `clean_accounts()` with a value for
                    // last_full_snapshot_slot that requires this archive call to succeed.
                    let (archive_result, archive_time_us) = measure_us!(snapshot_utils::serialize_and_archive_snapshot_package(
                        snapshot_package,
                        &snapshot_config,
                    ));
                    if let Err(err) = archive_result {
                        error!("Stopping SnapshotPackagerService! Fatal error while archiving snapshot package: {err}");
                        exit.store(true, Ordering::Relaxed);
                        break;
                    }


                    if let Some(snapshot_gossip_manager) = snapshot_gossip_manager.as_mut() {
                        snapshot_gossip_manager.push_snapshot_hash(snapshot_kind, (snapshot_slot, snapshot_hash));
                    }

                    let (_, purge_archives_time_us) = measure_us!(snapshot_utils::purge_old_snapshot_archives(
                        &snapshot_config.full_snapshot_archives_dir,
                        &snapshot_config.incremental_snapshot_archives_dir,
                        snapshot_config.maximum_full_snapshot_archives_to_retain,
                        snapshot_config.maximum_incremental_snapshot_archives_to_retain,
                    ));

                    // Now that this snapshot package has been archived, it is safe to remove
                    // all bank snapshots older than this slot.  We want to keep the bank
                    // snapshot *at this slot* so that it can be used during restarts, when
                    // booting from local state.
                    let (_, purge_bank_snapshots_time_us) = measure_us!(snapshot_utils::purge_bank_snapshots_older_than_slot(
                        &snapshot_config.bank_snapshots_dir,
                        snapshot_slot,
                    ));

                    let handling_time_us = measure_handling.end_as_us();
                    datapoint_info!(
                        "snapshot_packager_service",
                        (
                            "num_outstanding_snapshot_packages",
                            num_outstanding_snapshot_packages,
                            i64
                        ),
                        (
                            "num_re_enqueued_snapshot_packages",
                            num_re_enqueued_snapshot_packages,
                            i64
                        ),
                        ("enqueued_time_us", enqueued_time.as_micros(), i64),
                        ("handling_time_us", handling_time_us, i64),
                        ("archive_time_us", archive_time_us, i64),
                        (
                            "purge_old_snapshots_time_us",
                            purge_bank_snapshots_time_us,
                            i64
                        ),
                        (
                            "purge_old_archives_time_us",
                            purge_archives_time_us,
                            i64
                        ),
                    );
                }
                info!("SnapshotPackagerService has stopped");
            })
            .unwrap();

        Self {
            t_snapshot_packager,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_snapshot_packager.join()
    }

    /// Get the next snapshot package to handle
    ///
    /// Look through the snapshot package channel to find the highest priority one to handle next.
    /// If there are no snapshot packages in the channel, return None.  Otherwise return the
    /// highest priority one.  Unhandled snapshot packages with slots GREATER-THAN the handled one
    /// will be re-enqueued.  The remaining will be dropped.
    ///
    /// Also return the number of snapshot packages initially in the channel, and the number of
    /// ones re-enqueued.
    fn get_next_snapshot_package(
        snapshot_package_sender: &Sender<SnapshotPackage>,
        snapshot_package_receiver: &Receiver<SnapshotPackage>,
    ) -> Option<(
        SnapshotPackage,
        /*num outstanding snapshot packages*/ usize,
        /*num re-enqueued snapshot packages*/ usize,
    )> {
        let mut snapshot_packages: Vec<_> = snapshot_package_receiver.try_iter().collect();
        // `select_nth()` panics if the slice is empty, so return if that's the case
        if snapshot_packages.is_empty() {
            return None;
        }
        let snapshot_packages_len = snapshot_packages.len();
        debug!("outstanding snapshot packages ({snapshot_packages_len}): {snapshot_packages:?}");

        snapshot_packages.select_nth_unstable_by(
            snapshot_packages_len - 1,
            snapshot_package::cmp_snapshot_packages_by_priority,
        );
        // SAFETY: We know `snapshot_packages` is not empty, so its len is >= 1,
        // therefore there is always an element to pop.
        let snapshot_package = snapshot_packages.pop().unwrap();
        let handled_snapshot_package_slot = snapshot_package.slot;
        // re-enqueue any remaining snapshot packages for slots GREATER-THAN the snapshot package
        // that will be handled
        let num_re_enqueued_snapshot_packages = snapshot_packages
            .into_iter()
            .filter(|snapshot_package| snapshot_package.slot > handled_snapshot_package_slot)
            .map(|snapshot_package| {
                snapshot_package_sender
                    .try_send(snapshot_package)
                    .expect("re-enqueue snapshot package")
            })
            .count();

        Some((
            snapshot_package,
            snapshot_packages_len,
            num_re_enqueued_snapshot_packages,
        ))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        rand::seq::SliceRandom,
        solana_runtime::snapshot_package::{SnapshotKind, SnapshotPackage},
        solana_sdk::clock::Slot,
    };

    /// Ensure that unhandled snapshot packages are properly re-enqueued or dropped
    ///
    /// The snapshot package handler should re-enqueue unhandled snapshot packages, if those
    /// unhandled snapshot packages are for slots GREATER-THAN the last handled snapshot package.
    /// Otherwise, they should be dropped.
    #[test]
    fn test_get_next_snapshot_package() {
        fn new(snapshot_kind: SnapshotKind, slot: Slot) -> SnapshotPackage {
            SnapshotPackage {
                snapshot_kind,
                slot,
                block_height: slot,
                ..SnapshotPackage::default_for_tests()
            }
        }
        fn new_full(slot: Slot) -> SnapshotPackage {
            new(SnapshotKind::FullSnapshot, slot)
        }
        fn new_incr(slot: Slot, base: Slot) -> SnapshotPackage {
            new(SnapshotKind::IncrementalSnapshot(base), slot)
        }

        let (snapshot_package_sender, snapshot_package_receiver) = crossbeam_channel::unbounded();

        // Populate the channel so that re-enqueueing and dropping will be tested
        let mut snapshot_packages = [
            new_full(100),
            new_incr(110, 100),
            new_incr(210, 100),
            new_full(300),
            new_incr(310, 300),
            new_full(400), // <-- handle 1st
            new_incr(410, 400),
            new_incr(420, 400), // <-- handle 2nd
        ];
        // Shuffle the snapshot packages to simulate receiving new snapshot packages from AHV
        // simultaneously as SPS is handling them.
        snapshot_packages.shuffle(&mut rand::thread_rng());
        snapshot_packages
            .into_iter()
            .for_each(|snapshot_package| snapshot_package_sender.send(snapshot_package).unwrap());

        // The Full Snapshot from slot 400 is handled 1st
        // (the older full snapshots are skipped and dropped)
        let (
            snapshot_package,
            _num_outstanding_snapshot_packages,
            num_re_enqueued_snapshot_packages,
        ) = SnapshotPackagerService::get_next_snapshot_package(
            &snapshot_package_sender,
            &snapshot_package_receiver,
        )
        .unwrap();
        assert_eq!(snapshot_package.snapshot_kind, SnapshotKind::FullSnapshot,);
        assert_eq!(snapshot_package.slot, 400);
        assert_eq!(num_re_enqueued_snapshot_packages, 2);

        // The Incremental Snapshot from slot 420 is handled 2nd
        // (the older incremental snapshot from slot 410 is skipped and dropped)
        let (
            snapshot_package,
            _num_outstanding_snapshot_packages,
            num_re_enqueued_snapshot_packages,
        ) = SnapshotPackagerService::get_next_snapshot_package(
            &snapshot_package_sender,
            &snapshot_package_receiver,
        )
        .unwrap();
        assert_eq!(
            snapshot_package.snapshot_kind,
            SnapshotKind::IncrementalSnapshot(400),
        );
        assert_eq!(snapshot_package.slot, 420);
        assert_eq!(num_re_enqueued_snapshot_packages, 0);

        // And now the snapshot package channel is empty!
        assert!(SnapshotPackagerService::get_next_snapshot_package(
            &snapshot_package_sender,
            &snapshot_package_receiver
        )
        .is_none());
    }
}
