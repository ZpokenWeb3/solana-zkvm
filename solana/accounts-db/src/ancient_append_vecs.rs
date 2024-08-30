//! helpers for squashing append vecs into ancient append vecs
//! an ancient append vec is:
//! 1. a slot that is older than an epoch old
//! 2. multiple 'slots' squashed into a single older (ie. ancient) slot for convenience and performance
//! Otherwise, an ancient append vec is the same as any other append vec
use {
    crate::{
        account_storage::ShrinkInProgress,
        accounts_db::{
            AccountFromStorage, AccountStorageEntry, AccountsDb, AliveAccounts,
            GetUniqueAccountsResult, ShrinkAncientStats, ShrinkCollect,
            ShrinkCollectAliveSeparatedByRefs, ShrinkStatsSub,
        },
        accounts_file::AccountsFile,
        accounts_index::AccountsIndexScanResult,
        active_stats::ActiveStatItem,
        storable_accounts::{StorableAccounts, StorableAccountsBySlot},
    },
    rand::{thread_rng, Rng},
    rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    solana_measure::measure_us,
    solana_sdk::clock::Slot,
    std::{
        collections::HashMap,
        num::{NonZeroU64, Saturating},
        sync::{atomic::Ordering, Arc, Mutex},
    },
};

/// this many # of highest slot values should be treated as desirable to pack.
/// This gives us high slots to move packed accounts into.
const HIGH_SLOT_OFFSET: u64 = 100;

/// ancient packing algorithm tuning per pass
#[derive(Debug)]
struct PackedAncientStorageTuning {
    /// shrink enough of these ancient append vecs to realize this% of the total dead data that needs to be shrunk
    /// Doing too much burns too much time and disk i/o.
    /// Doing too little could cause us to never catch up and have old data accumulate.
    percent_of_alive_shrunk_data: u64,
    /// number of ancient slots we should aim to have. If we have more than this, combine further.
    max_ancient_slots: usize,
    /// # of bytes in an ideal ancient storage size
    ideal_storage_size: NonZeroU64,
    /// true if storages can be randomly shrunk even if they aren't eligible
    can_randomly_shrink: bool,
    /// limit the max # of output storages to prevent packing from running too long
    max_resulting_storages: NonZeroU64,
}

/// info about a storage eligible to be combined into an ancient append vec.
/// Useful to help sort vecs of storages.
#[derive(Debug)]
struct SlotInfo {
    storage: Arc<AccountStorageEntry>,
    /// slot of storage
    slot: Slot,
    /// total capacity of storage
    capacity: u64,
    /// # alive bytes in storage
    alive_bytes: u64,
    /// true if this should be shrunk due to ratio
    should_shrink: bool,
    /// this slot is a high slot #
    /// It is important to include some high slot #s so that we have new slots to try each time pack runs.
    is_high_slot: bool,
}

/// info for all storages in ancient slots
/// 'all_infos' contains all slots and storages that are ancient
#[derive(Default, Debug)]
struct AncientSlotInfos {
    /// info on all ancient storages
    all_infos: Vec<SlotInfo>,
    /// indexes to 'all_info' for storages that should be shrunk because alive ratio is too low.
    /// subset of all_infos
    shrink_indexes: Vec<usize>,
    /// total alive bytes across contents of 'shrink_indexes'
    total_alive_bytes_shrink: Saturating<u64>,
    /// total alive bytes across all slots
    total_alive_bytes: Saturating<u64>,
}

impl AncientSlotInfos {
    /// add info for 'storage'
    /// return true if item was randomly shrunk
    fn add(
        &mut self,
        slot: Slot,
        storage: Arc<AccountStorageEntry>,
        can_randomly_shrink: bool,
        ideal_size: NonZeroU64,
        is_high_slot: bool,
    ) -> bool {
        let mut was_randomly_shrunk = false;
        let alive_bytes = storage.alive_bytes() as u64;
        if alive_bytes > 0 {
            let capacity = storage.accounts.capacity();
            let should_shrink = if capacity > 0 {
                let alive_ratio = alive_bytes * 100 / capacity;
                alive_ratio < 90
                    || if can_randomly_shrink && thread_rng().gen_range(0..10000) == 0 {
                        was_randomly_shrunk = true;
                        true
                    } else {
                        false
                    }
            } else {
                false
            };
            // two criteria we're shrinking by later:
            // 1. alive ratio so that we don't consume too much disk space with dead accounts
            // 2. # of active ancient roots, so that we don't consume too many open file handles

            if should_shrink {
                // alive ratio is too low, so prioritize combining this slot with others
                // to reduce disk space used
                self.total_alive_bytes_shrink += alive_bytes;
                self.shrink_indexes.push(self.all_infos.len());
            } else {
                let already_ideal_size = u64::from(ideal_size) * 80 / 100;
                if alive_bytes > already_ideal_size {
                    // do not include this append vec at all. It is already ideal size and not a candidate for shrink.
                    return was_randomly_shrunk;
                }
            }
            self.all_infos.push(SlotInfo {
                slot,
                capacity,
                storage,
                alive_bytes,
                should_shrink,
                is_high_slot,
            });
            self.total_alive_bytes += alive_bytes;
        }
        was_randomly_shrunk
    }

    /// modify 'self' to contain only the slot infos for the slots that should be combined
    /// (and in this process effectively shrunk)
    fn filter_ancient_slots(
        &mut self,
        tuning: &PackedAncientStorageTuning,
        stats: &ShrinkAncientStats,
    ) {
        // figure out which slots to combine
        // 1. should_shrink: largest bytes saved above some cutoff of ratio
        self.choose_storages_to_shrink(tuning);
        // 2. smallest files so we get the largest number of files to remove
        self.filter_by_smallest_capacity(tuning, stats);
    }

    // sort 'shrink_indexes' by most bytes saved, highest to lowest
    fn sort_shrink_indexes_by_bytes_saved(&mut self) {
        self.shrink_indexes.sort_unstable_by(|l, r| {
            let amount_shrunk = |index: &usize| {
                let item = &self.all_infos[*index];
                item.capacity - item.alive_bytes
            };
            amount_shrunk(r).cmp(&amount_shrunk(l))
        });
    }

    /// clear 'should_shrink' for storages after a cutoff to limit how many storages we shrink
    fn clear_should_shrink_after_cutoff(&mut self, tuning: &PackedAncientStorageTuning) {
        let mut bytes_to_shrink_due_to_ratio = Saturating(0);
        // shrink enough slots to write 'percent_of_alive_shrunk_data'% of the total alive data
        // from slots that exceeded the shrink threshold.
        // The goal is to limit overall i/o in this pass while making progress.
        let threshold_bytes =
            self.total_alive_bytes_shrink.0 * tuning.percent_of_alive_shrunk_data / 100;
        for info_index in &self.shrink_indexes {
            let info = &mut self.all_infos[*info_index];
            if bytes_to_shrink_due_to_ratio.0 >= threshold_bytes {
                // we exceeded the amount to shrink due to alive ratio, so don't shrink this one just due to 'should_shrink'
                // It MAY be shrunk based on total capacity still.
                // Mark it as false for 'should_shrink' so it gets evaluated solely based on # of files.
                info.should_shrink = false;
            } else {
                bytes_to_shrink_due_to_ratio += info.alive_bytes;
            }
        }
    }

    /// after this function, only slots that were chosen to shrink are marked with
    /// 'should_shrink'
    /// There are likely more candidates to shrink than will be chosen.
    fn choose_storages_to_shrink(&mut self, tuning: &PackedAncientStorageTuning) {
        // sort the shrink_ratio_slots by most bytes saved to fewest
        // most bytes saved is more valuable to shrink
        self.sort_shrink_indexes_by_bytes_saved();

        self.clear_should_shrink_after_cutoff(tuning);
    }

    /// truncate 'all_infos' such that when the remaining entries in
    /// 'all_infos' are combined, the total number of storages <= 'max_storages'
    /// The idea is that 'all_infos' is sorted from smallest capacity to largest,
    /// but that isn't required for this function to be 'correct'.
    fn truncate_to_max_storages(
        &mut self,
        tuning: &PackedAncientStorageTuning,
        stats: &ShrinkAncientStats,
    ) {
        // these indexes into 'all_infos' are useless once we truncate 'all_infos', so make sure they're cleared out to avoid any issues
        self.shrink_indexes.clear();
        let total_storages = self.all_infos.len();
        let mut cumulative_bytes = Saturating(0u64);
        let low_threshold = tuning.max_ancient_slots * 50 / 100;
        let mut bytes_from_must_shrink = 0;
        let mut bytes_from_smallest_storages = 0;
        let mut bytes_from_newest_storages = 0;
        for (i, info) in self.all_infos.iter().enumerate() {
            cumulative_bytes += info.alive_bytes;
            let ancient_storages_required =
                div_ceil(cumulative_bytes.0, tuning.ideal_storage_size) as usize;
            let storages_remaining = total_storages - i - 1;

            // if the remaining uncombined storages and the # of resulting
            // combined ancient storages are less than the threshold, then
            // we've gone too far, so get rid of this entry and all after it.
            // Every storage after this one is larger than the ones we've chosen.
            // if we ever get to more than `max_resulting_storages` required ancient storages, that is enough to stop for now.
            // It will take a lot of time for the pack algorithm to create that many, and that is bad for system performance.
            // This should be a limit that only affects extreme testing environments.
            // We do not stop including entries until we have dealt with all the high slot #s. This allows the algorithm to continue
            // to make progress each time it is called. There are exceptions that can cause the pack to fail, such as accounts with multiple
            // refs.
            if !info.is_high_slot
                && (storages_remaining + ancient_storages_required < low_threshold
                    || ancient_storages_required as u64 > u64::from(tuning.max_resulting_storages))
            {
                self.all_infos.truncate(i);
                break;
            }
            if info.should_shrink {
                bytes_from_must_shrink += info.alive_bytes;
            } else if info.is_high_slot {
                bytes_from_newest_storages += info.alive_bytes;
            } else {
                bytes_from_smallest_storages += info.alive_bytes;
            }
        }
        stats
            .bytes_from_must_shrink
            .fetch_add(bytes_from_must_shrink, Ordering::Relaxed);
        stats
            .bytes_from_smallest_storages
            .fetch_add(bytes_from_smallest_storages, Ordering::Relaxed);
        stats
            .bytes_from_newest_storages
            .fetch_add(bytes_from_newest_storages, Ordering::Relaxed);
    }

    /// remove entries from 'all_infos' such that combining
    /// the remaining entries into storages of 'ideal_storage_size'
    /// will get us below 'max_storages'
    /// The entries that are removed will be reconsidered the next time around.
    /// Combining too many storages costs i/o and cpu so the goal is to find the sweet spot so
    /// that we make progress in cleaning/shrinking/combining but that we don't cause unnecessary
    /// churn.
    fn filter_by_smallest_capacity(
        &mut self,
        tuning: &PackedAncientStorageTuning,
        stats: &ShrinkAncientStats,
    ) {
        let total_storages = self.all_infos.len();
        if total_storages <= tuning.max_ancient_slots {
            // currently fewer storages than max, so nothing to shrink
            self.shrink_indexes.clear();
            self.all_infos.clear();
            return;
        }

        // sort by:
        // 1. `high_slot`: we want to include new, high slots each time so that we try new slots
        //     each time alg runs and have several high target slots for packed storages.
        // 2. 'should_shrink' so we make progress on shrinking ancient storages
        // 3. smallest capacity to largest so that we remove the most slots possible
        self.all_infos.sort_unstable_by(|l, r| {
            r.is_high_slot
                .cmp(&l.is_high_slot)
                .then_with(|| r.should_shrink.cmp(&l.should_shrink))
                .then_with(|| l.capacity.cmp(&r.capacity))
        });

        // remove any storages we don't need to combine this pass to achieve
        // # resulting storages <= 'max_storages'
        self.truncate_to_max_storages(tuning, stats);
    }
}

/// Used to hold the result of writing a single ancient storage
/// and results of writing multiple ancient storages
#[derive(Debug, Default)]
struct WriteAncientAccounts<'a> {
    /// 'ShrinkInProgress' instances created by starting a shrink operation
    shrinks_in_progress: HashMap<Slot, ShrinkInProgress<'a>>,

    metrics: ShrinkStatsSub,
}

#[derive(Debug, PartialEq, Clone, Copy)]
/// specify what to do with slots with accounts with many refs
enum IncludeManyRefSlots {
    /// include them in packing
    Include,
    // skip them. ie. don't include them until sufficient slots of single refs have been created
    Skip,
}

impl AccountsDb {
    /// Combine account data from storages in 'sorted_slots' into packed storages.
    /// This keeps us from accumulating storages for each slot older than an epoch.
    /// After this function the number of alive roots is <= # alive roots when it was called.
    /// In practice, the # of alive roots after will be significantly less than # alive roots when called.
    /// Trying to reduce # roots and storages (one per root) required to store all the data in ancient slots
    pub(crate) fn combine_ancient_slots_packed(
        &self,
        sorted_slots: Vec<Slot>,
        can_randomly_shrink: bool,
    ) {
        let tuning = PackedAncientStorageTuning {
            // only allow 10k slots old enough to be ancient
            max_ancient_slots: 10_000,
            // re-combine/shrink 55% of the data savings this pass
            percent_of_alive_shrunk_data: 55,
            ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
            can_randomly_shrink,
            max_resulting_storages: NonZeroU64::new(10).unwrap(),
        };

        let _guard = self.active_stats.activate(ActiveStatItem::SquashAncient);

        let mut stats_sub = ShrinkStatsSub::default();

        let (_, total_us) = measure_us!(self.combine_ancient_slots_packed_internal(
            sorted_slots,
            tuning,
            &mut stats_sub
        ));

        Self::update_shrink_stats(&self.shrink_ancient_stats.shrink_stats, stats_sub, false);
        self.shrink_ancient_stats
            .total_us
            .fetch_add(total_us, Ordering::Relaxed);

        self.shrink_ancient_stats.report();
    }

    /// return false if `many_refs_newest` accounts cannot be moved into `target_slots_sorted`.
    /// The slot # would be violated.
    /// accounts in `many_refs_newest` must be moved a slot >= each account's current slot.
    /// If that can be done, this fn returns true
    fn many_ref_accounts_can_be_moved(
        many_refs_newest: &[AliveAccounts<'_>],
        target_slots_sorted: &[Slot],
        tuning: &PackedAncientStorageTuning,
    ) -> bool {
        let alive_bytes = many_refs_newest
            .iter()
            .map(|alive| alive.bytes)
            .sum::<usize>();
        let required_ideal_packed = (alive_bytes as u64 / tuning.ideal_storage_size + 1) as usize;
        if alive_bytes == 0 {
            // nothing required, so no problem moving nothing
            return true;
        }
        if target_slots_sorted.len() < required_ideal_packed {
            return false;
        }
        let i_last = target_slots_sorted
            .len()
            .saturating_sub(required_ideal_packed);

        let highest_slot = target_slots_sorted[i_last];
        many_refs_newest
            .iter()
            .all(|many| many.slot <= highest_slot)
    }

    fn combine_ancient_slots_packed_internal(
        &self,
        sorted_slots: Vec<Slot>,
        tuning: PackedAncientStorageTuning,
        metrics: &mut ShrinkStatsSub,
    ) {
        self.shrink_ancient_stats
            .slots_considered
            .fetch_add(sorted_slots.len() as u64, Ordering::Relaxed);
        let ancient_slot_infos = self.collect_sort_filter_ancient_slots(sorted_slots, &tuning);

        if ancient_slot_infos.all_infos.is_empty() {
            return; // nothing to do
        }
        let mut accounts_per_storage = self
            .get_unique_accounts_from_storage_for_combining_ancient_slots(
                &ancient_slot_infos.all_infos[..],
            );

        let mut accounts_to_combine = self.calc_accounts_to_combine(
            &mut accounts_per_storage,
            &tuning,
            ancient_slot_infos.total_alive_bytes_shrink.0,
            IncludeManyRefSlots::Skip,
        );
        metrics.unpackable_slots_count += accounts_to_combine.unpackable_slots_count;

        let mut many_refs_newest = accounts_to_combine
            .accounts_to_combine
            .iter_mut()
            .filter_map(|alive| {
                let newest_alive =
                    std::mem::take(&mut alive.alive_accounts.many_refs_this_is_newest_alive);
                (!newest_alive.accounts.is_empty()).then_some(newest_alive)
            })
            .collect::<Vec<_>>();

        // Sort highest slot to lowest slot. This way, we will put the multi ref accounts with the highest slots in the highest
        // packed slot.
        many_refs_newest.sort_unstable_by(|a, b| b.slot.cmp(&a.slot));
        metrics.newest_alive_packed_count += many_refs_newest.len();

        if !Self::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &accounts_to_combine.target_slots_sorted,
            &tuning,
        ) {
            datapoint_info!("shrink_ancient_stats", ("high_slot", 1, i64));
            log::info!(
                "unable to ancient pack: highest available slot: {:?}, lowest required slot: {:?}",
                accounts_to_combine.target_slots_sorted.last(),
                many_refs_newest.last().map(|accounts| accounts.slot)
            );
            self.addref_accounts_failed_to_shrink_ancient(accounts_to_combine.accounts_to_combine);
            return;
        }

        // pack the accounts with 1 ref or refs > 1 but the slot we're packing is the highest alive slot for the pubkey.
        // Note the `chain` below combining the 2 types of refs.
        let pack = PackedAncientStorage::pack(
            many_refs_newest.iter().chain(
                accounts_to_combine
                    .accounts_to_combine
                    .iter()
                    .map(|shrink_collect| &shrink_collect.alive_accounts.one_ref),
            ),
            tuning.ideal_storage_size,
        );

        if pack.len() > accounts_to_combine.target_slots_sorted.len() {
            // Not enough slots to contain the accounts we are trying to pack.
            // `shrink_collect` previously unref'd some accounts. We need to addref them
            // to restore the correct state since we failed to combine anything.
            self.addref_accounts_failed_to_shrink_ancient(accounts_to_combine.accounts_to_combine);
            return;
        }

        let write_ancient_accounts = self.write_packed_storages(&accounts_to_combine, pack);

        self.finish_combine_ancient_slots_packed_internal(
            accounts_to_combine,
            write_ancient_accounts,
            metrics,
        );
    }

    /// for each account in `unrefed_pubkeys`, in each `accounts_to_combine`, addref
    fn addref_accounts_failed_to_shrink_ancient<'a>(
        &self,
        accounts_to_combine: Vec<ShrinkCollect<'a, ShrinkCollectAliveSeparatedByRefs<'a>>>,
    ) {
        self.thread_pool_clean.install(|| {
            accounts_to_combine.into_par_iter().for_each(|combine| {
                self.accounts_index.scan(
                    combine.unrefed_pubkeys.into_iter(),
                    |_pubkey, _slots_refs, entry| {
                        if let Some(entry) = entry {
                            entry.addref();
                        }
                        AccountsIndexScanResult::OnlyKeepInMemoryIfDirty
                    },
                    None,
                    true,
                );
            });
        });
    }

    /// calculate all storage info for the storages in slots
    /// Then, apply 'tuning' to filter out slots we do NOT want to combine.
    fn collect_sort_filter_ancient_slots(
        &self,
        slots: Vec<Slot>,
        tuning: &PackedAncientStorageTuning,
    ) -> AncientSlotInfos {
        let mut ancient_slot_infos = self.calc_ancient_slot_info(
            slots,
            tuning.can_randomly_shrink,
            tuning.ideal_storage_size,
        );

        ancient_slot_infos.filter_ancient_slots(tuning, &self.shrink_ancient_stats);
        ancient_slot_infos
    }

    /// create append vec of size 'bytes'
    /// write 'accounts_to_write' into it
    /// return shrink_in_progress and some metrics
    fn write_ancient_accounts<'a, 'b: 'a>(
        &'b self,
        bytes: u64,
        accounts_to_write: impl StorableAccounts<'a>,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        let target_slot = accounts_to_write.target_slot();
        let (shrink_in_progress, create_and_insert_store_elapsed_us) =
            measure_us!(self.get_store_for_shrink(target_slot, bytes));
        let (store_accounts_timing, rewrite_elapsed_us) = measure_us!(
            self.store_accounts_frozen(accounts_to_write, shrink_in_progress.new_storage(),)
        );

        write_ancient_accounts.metrics.accumulate(&ShrinkStatsSub {
            store_accounts_timing,
            rewrite_elapsed_us: Saturating(rewrite_elapsed_us),
            create_and_insert_store_elapsed_us: Saturating(create_and_insert_store_elapsed_us),
            ..ShrinkStatsSub::default()
        });

        write_ancient_accounts
            .shrinks_in_progress
            .insert(target_slot, shrink_in_progress);
    }
    /// go through all slots and populate 'SlotInfo', per slot
    /// This provides the list of possible ancient slots to sort, filter, and then combine.
    fn calc_ancient_slot_info(
        &self,
        slots: Vec<Slot>,
        can_randomly_shrink: bool,
        ideal_size: NonZeroU64,
    ) -> AncientSlotInfos {
        let len = slots.len();
        let mut infos = AncientSlotInfos {
            shrink_indexes: Vec::with_capacity(len),
            all_infos: Vec::with_capacity(len),
            ..AncientSlotInfos::default()
        };
        let mut randoms = 0;
        let max_slot = slots.iter().max().cloned().unwrap_or_default();
        // heuristic to include some # of newly eligible ancient slots so that the pack algorithm always makes progress
        let high_slot_boundary = max_slot.saturating_sub(HIGH_SLOT_OFFSET);
        let is_high_slot = |slot| slot >= high_slot_boundary;

        for slot in &slots {
            if let Some(storage) = self.storage.get_slot_storage_entry(*slot) {
                if infos.add(
                    *slot,
                    storage,
                    can_randomly_shrink,
                    ideal_size,
                    is_high_slot(*slot),
                ) {
                    randoms += 1;
                }
            }
        }
        if randoms > 0 {
            self.shrink_ancient_stats
                .random_shrink
                .fetch_add(randoms, Ordering::Relaxed);
        }
        infos
    }

    /// write packed storages as described in 'accounts_to_combine'
    /// and 'packed_contents'
    fn write_packed_storages<'a, 'b>(
        &'a self,
        accounts_to_combine: &'b AccountsToCombine<'b>,
        packed_contents: Vec<PackedAncientStorage<'b>>,
    ) -> WriteAncientAccounts<'a> {
        let write_ancient_accounts = Mutex::new(WriteAncientAccounts::default());

        // ok if we have more slots, but NOT ok if we have fewer slots than we have contents
        assert!(accounts_to_combine.target_slots_sorted.len() >= packed_contents.len());
        // write packed storages containing contents from many original slots
        // iterate slots in highest to lowest
        let packer = accounts_to_combine
            .target_slots_sorted
            .iter()
            .rev()
            .zip(packed_contents)
            .collect::<Vec<_>>();

        // keep track of how many slots were shrunk away
        self.shrink_ancient_stats
            .ancient_append_vecs_shrunk
            .fetch_add(
                accounts_to_combine
                    .target_slots_sorted
                    .len()
                    .saturating_sub(packer.len()) as u64,
                Ordering::Relaxed,
            );

        self.thread_pool_clean.install(|| {
            packer.par_iter().for_each(|(target_slot, pack)| {
                let mut write_ancient_accounts_local = WriteAncientAccounts::default();
                self.write_one_packed_storage(
                    pack,
                    **target_slot,
                    &mut write_ancient_accounts_local,
                );
                let mut write = write_ancient_accounts.lock().unwrap();
                write
                    .shrinks_in_progress
                    .extend(write_ancient_accounts_local.shrinks_in_progress);
                write
                    .metrics
                    .accumulate(&write_ancient_accounts_local.metrics);
            });
        });

        let mut write_ancient_accounts = write_ancient_accounts.into_inner().unwrap();

        // write new storages where contents were unable to move because ref_count > 1
        self.write_ancient_accounts_to_same_slot_multiple_refs(
            accounts_to_combine.accounts_keep_slots.values(),
            &mut write_ancient_accounts,
        );
        write_ancient_accounts
    }

    /// for each slot in 'ancient_slots', collect all accounts in that slot
    /// return the collection of accounts by slot
    fn get_unique_accounts_from_storage_for_combining_ancient_slots<'a>(
        &self,
        ancient_slots: &'a [SlotInfo],
    ) -> Vec<(&'a SlotInfo, GetUniqueAccountsResult)> {
        let mut accounts_to_combine = Vec::with_capacity(ancient_slots.len());

        for info in ancient_slots {
            let unique_accounts = self.get_unique_accounts_from_storage_for_shrink(
                &info.storage,
                &self.shrink_ancient_stats.shrink_stats,
            );
            accounts_to_combine.push((info, unique_accounts));
        }

        accounts_to_combine
    }

    /// finish shrink operation on slots where a new storage was created
    /// drop root and storage for all original slots whose contents were combined into other storages
    fn finish_combine_ancient_slots_packed_internal(
        &self,
        accounts_to_combine: AccountsToCombine<'_>,
        mut write_ancient_accounts: WriteAncientAccounts,
        metrics: &mut ShrinkStatsSub,
    ) {
        let mut dropped_roots = Vec::with_capacity(accounts_to_combine.accounts_to_combine.len());
        for shrink_collect in accounts_to_combine.accounts_to_combine {
            let slot = shrink_collect.slot;

            let shrink_in_progress = write_ancient_accounts.shrinks_in_progress.remove(&slot);
            if shrink_in_progress.is_none() {
                dropped_roots.push(slot);
            } else {
                self.reopen_storage_as_readonly_shrinking_in_progress_ok(slot);
            }
            self.remove_old_stores_shrink(
                &shrink_collect,
                &self.shrink_ancient_stats.shrink_stats,
                shrink_in_progress,
                true,
            );

            // If the slot is dead, remove the need to shrink the storage as the storage entries will be purged.
            self.shrink_candidate_slots.lock().unwrap().remove(&slot);
        }
        self.handle_dropped_roots_for_ancient(dropped_roots.into_iter());
        metrics.accumulate(&write_ancient_accounts.metrics);
    }

    /// given all accounts per ancient slot, in slots that we want to combine together:
    /// 1. Look up each pubkey in the index
    /// 2. separate, by slot, into:
    /// 2a. pubkeys with refcount = 1. This means this pubkey exists NOWHERE else in accounts db.
    /// 2b. pubkeys with refcount > 1
    /// Note that the return value can contain fewer items than 'accounts_per_storage' if we find storages which won't be affected.
    /// 'accounts_per_storage' should be sorted by slot
    fn calc_accounts_to_combine<'a>(
        &self,
        accounts_per_storage: &'a mut Vec<(&'a SlotInfo, GetUniqueAccountsResult)>,
        tuning: &PackedAncientStorageTuning,
        alive_bytes: u64,
        mut many_ref_slots: IncludeManyRefSlots,
    ) -> AccountsToCombine<'a> {
        // reverse sort by slot #
        accounts_per_storage.sort_unstable_by(|a, b| b.0.slot.cmp(&a.0.slot));
        let mut accounts_keep_slots = HashMap::default();
        let len = accounts_per_storage.len();
        let mut target_slots_sorted = Vec::with_capacity(len);

        // `shrink_collect` all accounts in the append vecs we want to combine.
        // This also unrefs all dead accounts in those append vecs.
        let mut accounts_to_combine = self.thread_pool_clean.install(|| {
            accounts_per_storage
                .par_iter()
                .map(|(info, unique_accounts)| {
                    self.shrink_collect::<ShrinkCollectAliveSeparatedByRefs<'_>>(
                        &info.storage,
                        unique_accounts,
                        &self.shrink_ancient_stats.shrink_stats,
                    )
                })
                .collect::<Vec<_>>()
        });

        let mut many_refs_old_alive_count = 0;

        // We want ceiling, so we add 1.
        // 0 < alive_bytes < `ideal_storage_size`, then `min_resulting_packed_slots` = 0.
        // We obviously require 1 packed slot if we have at 1 alive byte.
        let min_resulting_packed_slots =
            alive_bytes.saturating_sub(1) / u64::from(tuning.ideal_storage_size) + 1;
        let mut remove = Vec::default();
        let mut last_slot = None;
        for (i, (shrink_collect, (info, _unique_accounts))) in accounts_to_combine
            .iter_mut()
            .zip(accounts_per_storage.iter())
            .enumerate()
        {
            // assert that iteration is in descending slot order since the code below relies on this.
            if let Some(last_slot) = last_slot {
                assert!(last_slot > info.slot);
            }
            last_slot = Some(info.slot);

            let many_refs_old_alive = &mut shrink_collect.alive_accounts.many_refs_old_alive;
            if many_ref_slots == IncludeManyRefSlots::Skip
                && !shrink_collect
                    .alive_accounts
                    .many_refs_this_is_newest_alive
                    .accounts
                    .is_empty()
            {
                let mut required_packed_slots = min_resulting_packed_slots;
                if many_refs_old_alive.accounts.is_empty() {
                    // if THIS slot can be used as a target slot, then even if we have multi refs
                    // this is ok.
                    required_packed_slots = required_packed_slots.saturating_sub(1);
                }

                if (target_slots_sorted.len() as u64) >= required_packed_slots {
                    // we have prepared to pack enough normal target slots, that form now on we can safely pack
                    // any 'many ref' slots.
                    many_ref_slots = IncludeManyRefSlots::Include;
                } else {
                    // Skip this because too few valid slots have been processed so far.
                    // There are 'many ref newest' accounts in this slot. They must be packed into slots that are >= the current slot value.
                    // We require `min_resulting_packed_slots` target slots. If we have not encountered enough slots already without `many ref newest` accounts, then keep trying.
                    // On the next pass, THIS slot will be older relative to newly ancient slot #s, so those newly ancient slots will be higher in this list.
                    self.shrink_ancient_stats
                        .many_ref_slots_skipped
                        .fetch_add(1, Ordering::Relaxed);
                    remove.push(i);
                    continue;
                }
            }

            if !many_refs_old_alive.accounts.is_empty() {
                many_refs_old_alive_count += many_refs_old_alive.accounts.len();
                many_refs_old_alive.accounts.iter().for_each(|account| {
                    // these accounts could indicate clean bugs or low memory conditions where we are forced to flush non-roots
                    log::info!(
                        "ancient append vec: found unpackable account: {}, {}",
                        many_refs_old_alive.slot,
                        account.pubkey()
                    );
                });
                // There are alive accounts with ref_count > 1, where the entry for the account in the index is NOT the highest slot. (`many_refs_old_alive`)
                // This means this account must remain IN this slot. There could be alive or dead references to this same account in any older slot.
                // Moving it to a lower slot could move it before an alive or dead entry to this same account.
                // Moving it to a higher slot could move it ahead of other slots where this account is also alive. We know a higher slot exists that contains this account.
                // So, moving this account to a different slot could result in the moved account being before or after other instances of this account newer or older.
                // This would fail the invariant that the highest slot # where an account exists defines the most recent account.
                // It could be a clean error or a transient condition that will resolve if we encounter this situation.
                // The count of these accounts per call will be reported by metrics in `unpackable_slots_count`
                if shrink_collect.unrefed_pubkeys.is_empty()
                    && shrink_collect.alive_accounts.one_ref.accounts.is_empty()
                    && shrink_collect
                        .alive_accounts
                        .many_refs_this_is_newest_alive
                        .accounts
                        .is_empty()
                {
                    // all accounts in this append vec are alive and have > 1 ref, so nothing to be done for this append vec
                    remove.push(i);
                    continue;
                }
                accounts_keep_slots.insert(info.slot, std::mem::take(many_refs_old_alive));
            } else {
                // No alive accounts in this slot have a ref_count > 1. So, ALL alive accounts in this slot can be written to any other slot
                // we find convenient. There is NO other instance of any account to conflict with.
                target_slots_sorted.push(info.slot);
            }
        }
        let unpackable_slots_count = remove.len();
        remove.into_iter().rev().for_each(|i| {
            self.addref_accounts_failed_to_shrink_ancient(vec![accounts_to_combine.remove(i)]);
        });
        target_slots_sorted.sort_unstable();
        self.shrink_ancient_stats
            .slots_cannot_move_count
            .fetch_add(accounts_keep_slots.len() as u64, Ordering::Relaxed);
        self.shrink_ancient_stats
            .many_refs_old_alive
            .fetch_add(many_refs_old_alive_count as u64, Ordering::Relaxed);
        AccountsToCombine {
            accounts_to_combine,
            accounts_keep_slots,
            target_slots_sorted,
            unpackable_slots_count,
        }
    }

    /// create packed storage and write contents of 'packed' to it.
    /// accumulate results in 'write_ancient_accounts'
    fn write_one_packed_storage<'a, 'b: 'a>(
        &'b self,
        packed: &'a PackedAncientStorage<'a>,
        target_slot: Slot,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        let PackedAncientStorage {
            bytes: bytes_total,
            accounts: accounts_to_write,
        } = packed;
        let accounts_to_write = StorableAccountsBySlot::new(target_slot, accounts_to_write, self);

        self.shrink_ancient_stats
            .bytes_ancient_created
            .fetch_add(packed.bytes, Ordering::Relaxed);
        self.shrink_ancient_stats
            .shrink_stats
            .num_slots_shrunk
            .fetch_add(1, Ordering::Relaxed);
        self.write_ancient_accounts(*bytes_total, accounts_to_write, write_ancient_accounts)
    }

    /// For each slot and alive accounts in 'accounts_to_combine'
    /// create a PackedAncientStorage that only contains the given alive accounts.
    /// This will represent only the accounts with ref_count > 1 from the original storage.
    /// These accounts need to be rewritten in their same slot, Ideally with no other accounts in the slot.
    /// Other accounts would have ref_count = 1.
    /// ref_count = 1 accounts will be combined together with other slots into larger append vecs elsewhere.
    fn write_ancient_accounts_to_same_slot_multiple_refs<'a, 'b: 'a>(
        &'b self,
        accounts_to_combine: impl Iterator<Item = &'a AliveAccounts<'a>>,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        for alive_accounts in accounts_to_combine {
            let packed = PackedAncientStorage {
                bytes: alive_accounts.bytes as u64,
                accounts: vec![(alive_accounts.slot, &alive_accounts.accounts[..])],
            };

            self.write_one_packed_storage(&packed, alive_accounts.slot, write_ancient_accounts);
        }
    }
}

/// hold all alive accounts to be shrunk and/or combined
#[derive(Debug, Default)]
struct AccountsToCombine<'a> {
    /// slots and alive accounts that must remain in the slot they are currently in
    /// because the account exists in more than 1 slot in accounts db
    /// This hashmap contains an entry for each slot that contains at least one account with ref_count > 1.
    /// The value of the entry is all alive accounts in that slot whose ref_count > 1.
    /// Any OTHER accounts in that slot whose ref_count = 1 are in 'accounts_to_combine' because they can be moved
    /// to any slot.
    /// We want to keep the ref_count > 1 accounts by themselves, expecting the multiple ref_counts will be resolved
    /// soon and we can clean the duplicates up (which maybe THIS one).
    accounts_keep_slots: HashMap<Slot, AliveAccounts<'a>>,
    /// all the rest of alive accounts that can move slots and should be combined
    /// This includes all accounts with ref_count = 1 from the slots in 'accounts_keep_slots'.
    /// There is one entry here for each storage we are processing. Even if all accounts are in 'accounts_keep_slots'.
    accounts_to_combine: Vec<ShrinkCollect<'a, ShrinkCollectAliveSeparatedByRefs<'a>>>,
    /// slots that contain alive accounts that can move into ANY other ancient slot
    /// these slots will NOT be in 'accounts_keep_slots'
    /// Some of these slots will have ancient append vecs created at them to contain everything in 'accounts_to_combine'
    /// The rest will become dead slots with no accounts in them.
    /// Sort order is lowest to highest.
    target_slots_sorted: Vec<Slot>,
    /// when scanning, this many slots contained accounts that could not be packed because accounts with ref_count > 1 existed.
    unpackable_slots_count: usize,
}

#[derive(Default)]
/// intended contents of a packed ancient storage
struct PackedAncientStorage<'a> {
    /// accounts to move into this storage, along with the slot the accounts are currently stored in
    accounts: Vec<(Slot, &'a [&'a AccountFromStorage])>,
    /// total bytes required to hold 'accounts'
    bytes: u64,
}

impl<'a> PackedAncientStorage<'a> {
    /// return a minimal set of 'PackedAncientStorage's to contain all 'accounts_to_combine' with
    /// the new storages having a size guided by 'ideal_size'
    fn pack(
        mut accounts_to_combine: impl Iterator<Item = &'a AliveAccounts<'a>>,
        ideal_size: NonZeroU64,
    ) -> Vec<PackedAncientStorage<'a>> {
        let mut result = Vec::default();
        let ideal_size: u64 = ideal_size.into();
        let ideal_size = ideal_size as usize;
        let mut current_alive_accounts = accounts_to_combine.next();
        // starting at first entry in current_alive_accounts
        let mut partial_inner_index = 0;
        // 0 bytes written so far from the current set of accounts
        let mut partial_bytes_written = Saturating(0);
        // pack a new storage each iteration of this outer loop
        loop {
            let mut bytes_total = 0usize;
            let mut accounts_to_write = Vec::default();

            // walk through each set of alive accounts to pack the current new storage up to ideal_size
            let mut full = false;
            while !full && current_alive_accounts.is_some() {
                let alive_accounts = current_alive_accounts.unwrap();
                if partial_inner_index >= alive_accounts.accounts.len() {
                    // current_alive_accounts have all been written, so advance to next set from accounts_to_combine
                    current_alive_accounts = accounts_to_combine.next();
                    // reset partial progress since we're starting over with a new set of alive accounts
                    partial_inner_index = 0;
                    partial_bytes_written = Saturating(0);
                    continue;
                }
                let bytes_remaining_this_slot =
                    alive_accounts.bytes.saturating_sub(partial_bytes_written.0);
                let bytes_total_with_this_slot =
                    bytes_total.saturating_add(bytes_remaining_this_slot);
                let mut partial_inner_index_max_exclusive;
                if bytes_total_with_this_slot <= ideal_size {
                    partial_inner_index_max_exclusive = alive_accounts.accounts.len();
                    bytes_total = bytes_total_with_this_slot;
                } else {
                    partial_inner_index_max_exclusive = partial_inner_index;
                    // adding all the alive accounts in this storage would exceed the ideal size, so we have to break these accounts up
                    // look at each account and stop when we exceed the ideal size
                    while partial_inner_index_max_exclusive < alive_accounts.accounts.len() {
                        let account = alive_accounts.accounts[partial_inner_index_max_exclusive];
                        let account_size = account.stored_size();
                        let new_size = bytes_total.saturating_add(account_size);
                        if new_size > ideal_size && bytes_total > 0 {
                            full = true;
                            // partial_inner_index_max_exclusive is the index of the first account that puts us over the ideal size
                            // so, save it for next time
                            break;
                        }
                        // this account fits
                        partial_bytes_written += account_size;
                        bytes_total = new_size;
                        partial_inner_index_max_exclusive += 1;
                    }
                }

                if partial_inner_index < partial_inner_index_max_exclusive {
                    // these accounts belong in the current packed storage we're working on
                    accounts_to_write.push((
                        alive_accounts.slot,
                        // maybe all alive accounts from the current or could be partial
                        &alive_accounts.accounts
                            [partial_inner_index..partial_inner_index_max_exclusive],
                    ));
                }
                // start next storage with the account we ended with
                // this could be the end of the current alive accounts or could be anywhere within that vec
                partial_inner_index = partial_inner_index_max_exclusive;
            }
            if accounts_to_write.is_empty() {
                // if we returned without any accounts to write, then we have exhausted source data and have packaged all the storages we need
                break;
            }
            // we know the full contents of this packed storage now
            result.push(PackedAncientStorage {
                bytes: bytes_total as u64,
                accounts: accounts_to_write,
            });
        }
        result
    }
}

/// a set of accounts need to be stored.
/// If there are too many to fit in 'Primary', the rest are put in 'Overflow'
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StorageSelector {
    Primary,
    Overflow,
}

/// reference a set of accounts to store
/// The accounts may have to be split between 2 storages (primary and overflow) if there is not enough room in the primary storage.
/// The 'store' functions need data stored in a slice of specific type.
/// We need 1-2 of these slices constructed based on available bytes and individual account sizes.
/// The slice arithmetic across both hashes and account data gets messy. So, this struct abstracts that.
pub struct AccountsToStore<'a> {
    accounts: &'a [&'a AccountFromStorage],
    /// if 'accounts' contains more items than can be contained in the primary storage, then we have to split these accounts.
    /// 'index_first_item_overflow' specifies the index of the first item in 'accounts' that will go into the overflow storage
    index_first_item_overflow: usize,
    slot: Slot,
    /// bytes required to store primary accounts
    bytes_primary: usize,
    /// bytes required to store overflow accounts
    bytes_overflow: usize,
}

impl<'a> AccountsToStore<'a> {
    /// break 'stored_accounts' into primary and overflow
    /// available_bytes: how many bytes remain in the primary storage. Excess accounts will be directed to an overflow storage
    pub fn new(
        mut available_bytes: u64,
        accounts: &'a [&'a AccountFromStorage],
        alive_total_bytes: usize,
        slot: Slot,
    ) -> Self {
        let num_accounts = accounts.len();
        let mut bytes_primary = alive_total_bytes;
        let mut bytes_overflow = 0;
        // index of the first account that doesn't fit in the current append vec
        let mut index_first_item_overflow = num_accounts; // assume all fit
        let initial_available_bytes = available_bytes as usize;
        if alive_total_bytes > available_bytes as usize {
            // not all the alive bytes fit, so we have to find how many accounts fit within available_bytes
            for (i, account) in accounts.iter().enumerate() {
                let account_size = account.stored_size() as u64;
                if available_bytes >= account_size {
                    available_bytes = available_bytes.saturating_sub(account_size);
                } else if index_first_item_overflow == num_accounts {
                    // the # of accounts we have so far seen is the most that will fit in the current ancient append vec
                    index_first_item_overflow = i;
                    bytes_primary =
                        initial_available_bytes.saturating_sub(available_bytes as usize);
                    bytes_overflow = alive_total_bytes.saturating_sub(bytes_primary);
                    break;
                }
            }
        }
        Self {
            accounts,
            index_first_item_overflow,
            slot,
            bytes_primary,
            bytes_overflow,
        }
    }

    /// true if a request to 'get' 'Overflow' would return accounts & hashes
    pub fn has_overflow(&self) -> bool {
        self.index_first_item_overflow < self.accounts.len()
    }

    /// return # required bytes for the given selector
    pub fn get_bytes(&self, selector: StorageSelector) -> usize {
        match selector {
            StorageSelector::Primary => self.bytes_primary,
            StorageSelector::Overflow => self.bytes_overflow,
        }
    }

    /// get the accounts to store in the given 'storage'
    pub fn get(&self, storage: StorageSelector) -> &[&'a AccountFromStorage] {
        let range = match storage {
            StorageSelector::Primary => 0..self.index_first_item_overflow,
            StorageSelector::Overflow => self.index_first_item_overflow..self.accounts.len(),
        };
        &self.accounts[range]
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }
}

/// capacity of an ancient append vec
#[allow(clippy::assertions_on_constants, dead_code)]
pub const fn get_ancient_append_vec_capacity() -> u64 {
    // There is a trade-off for selecting the ancient append vec size. Smaller non-ancient append vec are getting
    // combined into large ancient append vec. Too small size of ancient append vec will result in too many ancient append vec
    // memory mapped files. Too big size will make it difficult to clean and shrink them. Hence, we choose approximately
    // 128MB for the ancient append vec size.
    const RESULT: u64 = 128 * 1024 * 1024;

    use crate::append_vec::MAXIMUM_APPEND_VEC_FILE_SIZE;
    const _: () = assert!(
        RESULT < MAXIMUM_APPEND_VEC_FILE_SIZE,
        "ancient append vec size should be less than the maximum append vec size"
    );
    const PAGE_SIZE: u64 = 4 * 1024;
    const _: () = assert!(
        RESULT % PAGE_SIZE == 0,
        "ancient append vec size should be a multiple of PAGE_SIZE"
    );

    RESULT
}

/// is this a max-size append vec designed to be used as an ancient append vec?
pub fn is_ancient(storage: &AccountsFile) -> bool {
    storage.capacity() >= get_ancient_append_vec_capacity()
}

/// Divides `x` by `y` and rounds up
///
/// # Notes
///
/// It is undefined behavior if `x + y` overflows a u64.
/// Debug builds check this invariant, and will panic if broken.
fn div_ceil(x: u64, y: NonZeroU64) -> u64 {
    let y = y.get();
    debug_assert!(
        x.checked_add(y).is_some(),
        "x + y must not overflow! x: {x}, y: {y}",
    );
    // SAFETY: The caller guaranteed `x + y` does not overflow
    // SAFETY: Since `y` is NonZero:
    // - we know the denominator is > 0, and thus safe (cannot have divide-by-zero)
    // - we know `x + y` is non-zero, and thus the numerator is safe (cannot underflow)
    (x + y - 1) / y
}

#[cfg(test)]
pub mod tests {
    use {
        super::*,
        crate::{
            account_info::{AccountInfo, StorageLocation},
            account_storage::meta::{AccountMeta, StoredAccountMeta, StoredMeta},
            accounts_db::{
                get_temp_accounts_paths,
                tests::{
                    append_single_account_with_default_hash, compare_all_accounts,
                    create_db_with_storages_and_index, create_storages_and_update_index,
                    get_account_from_account_from_storage, get_all_accounts,
                    remove_account_for_tests, CAN_RANDOMLY_SHRINK_FALSE,
                },
                ShrinkCollectRefs,
            },
            accounts_hash::AccountHash,
            accounts_index::UpsertReclaim,
            append_vec::{
                aligned_stored_size, AppendVec, AppendVecStoredAccountMeta,
                MAXIMUM_APPEND_VEC_FILE_SIZE,
            },
            storable_accounts::{tests::build_accounts_from_storage, StorableAccountsBySlot},
        },
        rand::seq::SliceRandom as _,
        solana_sdk::{
            account::{AccountSharedData, ReadableAccount, WritableAccount},
            hash::Hash,
            pubkey::Pubkey,
        },
        std::{collections::HashSet, ops::Range},
        strum::IntoEnumIterator,
        strum_macros::EnumIter,
        test_case::test_case,
    };

    fn get_sample_storages(
        slots: usize,
        account_data_size: Option<u64>,
    ) -> (
        AccountsDb,
        Vec<Arc<AccountStorageEntry>>,
        Range<u64>,
        Vec<SlotInfo>,
    ) {
        let alive = true;
        let (db, slot1) = create_db_with_storages_and_index(alive, slots, account_data_size);
        let original_stores = (0..slots)
            .filter_map(|slot| db.storage.get_slot_storage_entry((slot as Slot) + slot1))
            .collect::<Vec<_>>();
        let is_high_slot = false;
        let slot_infos = original_stores
            .iter()
            .map(|storage| SlotInfo {
                storage: Arc::clone(storage),
                slot: storage.slot(),
                capacity: 0,
                alive_bytes: 0,
                should_shrink: false,
                is_high_slot,
            })
            .collect();
        (
            db,
            original_stores,
            slot1..(slot1 + slots as Slot),
            slot_infos,
        )
    }

    fn unique_to_accounts<'a>(
        one: impl Iterator<Item = &'a GetUniqueAccountsResult>,
        db: &AccountsDb,
        slot: Slot,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        one.flat_map(|result| {
            result.stored_accounts.iter().map(|result| {
                (
                    *result.pubkey(),
                    get_account_from_account_from_storage(result, db, slot),
                )
            })
        })
        .collect()
    }

    pub(crate) fn compare_all_vec_accounts<'a>(
        one: impl Iterator<Item = &'a GetUniqueAccountsResult>,
        two: impl Iterator<Item = &'a GetUniqueAccountsResult>,
        db: &AccountsDb,
        slot: Slot,
    ) {
        compare_all_accounts(
            &unique_to_accounts(one, db, slot),
            &unique_to_accounts(two, db, slot),
        );
    }

    #[test]
    fn test_write_packed_storages_empty() {
        let (db, _storages, _slots, _infos) = get_sample_storages(0, None);
        let write_ancient_accounts =
            db.write_packed_storages(&AccountsToCombine::default(), Vec::default());
        assert!(write_ancient_accounts.shrinks_in_progress.is_empty());
    }

    #[test]
    #[should_panic(
        expected = "accounts_to_combine.target_slots_sorted.len() >= packed_contents.len()"
    )]
    fn test_write_packed_storages_too_few_slots() {
        let (db, storages, slots, _infos) = get_sample_storages(1, None);
        let accounts_to_combine = AccountsToCombine::default();
        let account = storages
            .first()
            .unwrap()
            .accounts
            .get_stored_account_meta_callback(0, |account| AccountFromStorage::new(&account))
            .unwrap();
        let accounts = [&account];

        let packed_contents = vec![PackedAncientStorage {
            bytes: 0,
            accounts: vec![(slots.start, &accounts[..])],
        }];
        db.write_packed_storages(&accounts_to_combine, packed_contents);
    }

    #[test]
    fn test_write_ancient_accounts_to_same_slot_multiple_refs_empty() {
        let (db, _storages, _slots, _infos) = get_sample_storages(0, None);
        let mut write_ancient_accounts = WriteAncientAccounts::default();
        db.write_ancient_accounts_to_same_slot_multiple_refs(
            AccountsToCombine::default().accounts_keep_slots.values(),
            &mut write_ancient_accounts,
        );
        assert!(write_ancient_accounts.shrinks_in_progress.is_empty());
    }

    #[test]
    fn test_pack_ancient_storages_one_account_per_storage() {
        for num_slots in 0..4 {
            for (ideal_size, expected_storages) in [
                (1, num_slots),
                (get_ancient_append_vec_capacity(), 1.min(num_slots)),
            ] {
                let (db, storages, slots, _infos) = get_sample_storages(num_slots, None);
                let original_results = storages
                    .iter()
                    .map(|store| db.get_unique_accounts_from_storage(store))
                    .collect::<Vec<_>>();

                let slots_vec = slots.collect::<Vec<_>>();
                let accounts_to_combine = original_results
                    .iter()
                    .zip(slots_vec.iter().cloned())
                    .map(|(accounts, slot)| AliveAccounts {
                        accounts: accounts.stored_accounts.iter().collect::<Vec<_>>(),
                        bytes: accounts
                            .stored_accounts
                            .iter()
                            .map(|account| aligned_stored_size(account.data_len()))
                            .sum(),
                        slot,
                    })
                    .collect::<Vec<_>>();

                let result = PackedAncientStorage::pack(
                    accounts_to_combine.iter(),
                    NonZeroU64::new(ideal_size).unwrap(),
                );
                let storages_needed = result.len();
                assert_eq!(storages_needed, expected_storages);
            }
        }
    }

    #[test]
    fn test_pack_ancient_storages_one_partial() {
        // n slots
        // m accounts per slot
        // divide into different ideal sizes so that we combine multiple slots sometimes and combine partial slots
        solana_logger::setup();
        let total_accounts_per_storage = 10;
        let account_size = 184;
        for num_slots in 0..4 {
            for (ideal_size, expected_storages) in [
                (1, num_slots * total_accounts_per_storage),
                (account_size - 1, num_slots * total_accounts_per_storage),
                (account_size, num_slots * total_accounts_per_storage),
                (account_size + 1, num_slots * total_accounts_per_storage),
                (account_size * 2 - 1, num_slots * total_accounts_per_storage),
                (account_size * 2, num_slots * total_accounts_per_storage / 2),
                (get_ancient_append_vec_capacity(), 1.min(num_slots)),
            ] {
                let (db, storages, slots, _infos) = get_sample_storages(num_slots, None);

                let account_template = storages
                    .first()
                    .and_then(|storage| storage.accounts.get_account_shared_data(0))
                    .unwrap_or_default();
                // add some accounts to each storage so we can make partial progress
                let mut lamports = 1000;
                let _pubkeys_and_accounts = storages
                    .iter()
                    .map(|storage| {
                        (0..(total_accounts_per_storage - 1))
                            .map(|_| {
                                let pk = solana_sdk::pubkey::new_rand();
                                let mut account = account_template.clone();
                                account.set_lamports(lamports);
                                lamports += 1;
                                append_single_account_with_default_hash(
                                    storage,
                                    &pk,
                                    &account,
                                    true,
                                    Some(&db.accounts_index),
                                );
                                (pk, account)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let original_results = storages
                    .iter()
                    .map(|store| (store.slot(), db.get_unique_accounts_from_storage(store)))
                    .collect::<Vec<_>>();
                let original_results_all_accounts = vec_unique_to_accounts(&original_results, &db);

                let slots_vec = slots.clone().collect::<Vec<_>>();
                let accounts_to_combine = original_results
                    .iter()
                    .zip(slots_vec.iter().cloned())
                    .map(|((_slot, accounts), slot)| AliveAccounts {
                        accounts: accounts.stored_accounts.iter().collect::<Vec<_>>(),
                        bytes: accounts
                            .stored_accounts
                            .iter()
                            .map(|account| aligned_stored_size(account.data_len()))
                            .sum(),
                        slot,
                    })
                    .collect::<Vec<_>>();

                let result = PackedAncientStorage::pack(
                    accounts_to_combine.iter(),
                    NonZeroU64::new(ideal_size).unwrap(),
                );
                let storages_needed = result.len();
                assert_eq!(storages_needed, expected_storages, "num_slots: {num_slots}, expected_storages: {expected_storages}, storages_needed: {storages_needed}, ideal_size: {ideal_size}");
                compare_all_accounts(
                    &packed_to_compare(&result, &db)[..],
                    &original_results_all_accounts,
                );
            }
        }
    }

    fn packed_to_compare(
        packed: &[PackedAncientStorage],
        db: &AccountsDb,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        packed
            .iter()
            .flat_map(|packed| {
                packed.accounts.iter().flat_map(|(slot, stored_metas)| {
                    stored_metas.iter().map(|stored_meta| {
                        (
                            *stored_meta.pubkey(),
                            get_account_from_account_from_storage(stored_meta, db, *slot),
                        )
                    })
                })
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_pack_ancient_storages_varying() {
        // n slots
        // different number of accounts in each slot
        // each account has different size
        // divide into different ideal sizes so that we combine multiple slots sometimes and combine partial slots
        // compare at end that all accounts are in result exactly once
        solana_logger::setup();
        let total_accounts_per_storage = 10;
        let account_size = 184;
        for num_slots in 0..4 {
            for ideal_size in [
                1,
                account_size - 1,
                account_size,
                account_size + 1,
                account_size * 2 - 1,
                account_size * 2,
                get_ancient_append_vec_capacity(),
            ] {
                let (db, storages, slots, _infos) = get_sample_storages(num_slots, None);

                let account_template = storages
                    .first()
                    .and_then(|storage| storage.accounts.get_account_shared_data(0))
                    .unwrap_or_default();
                // add some accounts to each storage so we can make partial progress
                let mut data_size = 450;
                // random # of extra accounts here
                let total_accounts_per_storage =
                    thread_rng().gen_range(0..total_accounts_per_storage);
                let _pubkeys_and_accounts = storages
                    .iter()
                    .map(|storage| {
                        (0..(total_accounts_per_storage - 1))
                            .map(|_| {
                                let pk = solana_sdk::pubkey::new_rand();
                                let mut account = account_template.clone();
                                account.set_data((0..data_size).map(|x| (x % 256) as u8).collect());
                                data_size += 1;
                                append_single_account_with_default_hash(
                                    storage,
                                    &pk,
                                    &account,
                                    true,
                                    Some(&db.accounts_index),
                                );
                                (pk, account)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let original_results = storages
                    .iter()
                    .map(|store| (store.slot(), db.get_unique_accounts_from_storage(store)))
                    .collect::<Vec<_>>();
                let original_results_all_accounts = vec_unique_to_accounts(&original_results, &db);

                let slots_vec = slots.clone().collect::<Vec<_>>();
                let accounts_to_combine = original_results
                    .iter()
                    .zip(slots_vec.iter().cloned())
                    .map(|((_slot, accounts), slot)| AliveAccounts {
                        accounts: accounts.stored_accounts.iter().collect::<Vec<_>>(),
                        bytes: accounts
                            .stored_accounts
                            .iter()
                            .map(|account| aligned_stored_size(account.data_len()))
                            .sum(),
                        slot,
                    })
                    .collect::<Vec<_>>();

                let result = PackedAncientStorage::pack(
                    accounts_to_combine.iter(),
                    NonZeroU64::new(ideal_size).unwrap(),
                );

                let largest_account_size = aligned_stored_size(data_size) as u64;
                // all packed storages should be close to ideal size
                result.iter().enumerate().for_each(|(i, packed)| {
                    if i + 1 < result.len() && ideal_size > largest_account_size {
                        // cannot assert this on the last packed storage - it may be small
                        // cannot assert this when the ideal size is too small to hold the largest account size
                        assert!(
                            packed.bytes >= ideal_size - largest_account_size,
                            "packed size too small: bytes: {}, ideal: {}, largest: {}",
                            packed.bytes,
                            ideal_size,
                            largest_account_size
                        );
                    }
                    assert!(
                        packed.bytes > 0,
                        "packed size of zero"
                    );
                    assert!(
                        packed.bytes <= ideal_size || packed.accounts.iter().map(|(_slot, accounts)| accounts.len()).sum::<usize>() == 1,
                        "packed size too large: bytes: {}, ideal_size: {}, data_size: {}, num_slots: {}, # accounts: {}",
                        packed.bytes,
                        ideal_size,
                        data_size,
                        num_slots,
                        packed.accounts.len()
                    );
                });
                result.iter().for_each(|packed| {
                    assert_eq!(
                        packed.bytes,
                        packed
                            .accounts
                            .iter()
                            .map(|(_slot, accounts)| accounts
                                .iter()
                                .map(|account| aligned_stored_size(account.data_len()) as u64)
                                .sum::<u64>())
                            .sum::<u64>()
                    );
                });

                compare_all_accounts(
                    &packed_to_compare(&result, &db)[..],
                    &original_results_all_accounts,
                );
            }
        }
    }

    #[derive(EnumIter, Debug, PartialEq, Eq)]
    enum TestWriteMultipleRefs {
        MultipleRefs,
        PackedStorages,
    }

    #[test]
    fn test_finish_combine_ancient_slots_packed_internal() {
        // n storages
        // 1 account each
        // all accounts have 1 ref
        // nothing shrunk, so all storages and roots should be removed
        // or all slots shrunk so no roots or storages should be removed
        for in_shrink_candidate_slots in [false, true] {
            for all_slots_shrunk in [false, true] {
                for num_slots in 0..3 {
                    let (db, storages, slots, infos) = get_sample_storages(num_slots, None);
                    let mut accounts_per_storage = infos
                        .iter()
                        .zip(
                            storages
                                .iter()
                                .map(|store| db.get_unique_accounts_from_storage(store)),
                        )
                        .collect::<Vec<_>>();

                    let alive_bytes = 1000;
                    let accounts_to_combine = db.calc_accounts_to_combine(
                        &mut accounts_per_storage,
                        &default_tuning(),
                        alive_bytes,
                        IncludeManyRefSlots::Include,
                    );
                    let mut stats = ShrinkStatsSub::default();
                    let mut write_ancient_accounts = WriteAncientAccounts::default();

                    slots.clone().for_each(|slot| {
                        db.add_root(slot);
                        let storage = db.storage.get_slot_storage_entry(slot);
                        assert!(storage.is_some());
                        if in_shrink_candidate_slots {
                            db.shrink_candidate_slots.lock().unwrap().insert(slot);
                        }
                    });

                    let roots = db
                        .accounts_index
                        .roots_tracker
                        .read()
                        .unwrap()
                        .alive_roots
                        .get_all();
                    assert_eq!(roots, slots.clone().collect::<Vec<_>>());

                    if all_slots_shrunk {
                        // make it look like each of the slots was shrunk
                        slots.clone().for_each(|slot| {
                            write_ancient_accounts
                                .shrinks_in_progress
                                .insert(slot, db.get_store_for_shrink(slot, 1));
                        });
                    }

                    db.finish_combine_ancient_slots_packed_internal(
                        accounts_to_combine,
                        write_ancient_accounts,
                        &mut stats,
                    );

                    slots.clone().for_each(|slot| {
                        assert!(!db.shrink_candidate_slots.lock().unwrap().contains(&slot));
                    });

                    let roots_after = db
                        .accounts_index
                        .roots_tracker
                        .read()
                        .unwrap()
                        .alive_roots
                        .get_all();

                    assert_eq!(
                        roots_after,
                        if all_slots_shrunk {
                            slots.clone().collect::<Vec<_>>()
                        } else {
                            vec![]
                        },
                        "all_slots_shrunk: {all_slots_shrunk}"
                    );
                    slots.for_each(|slot| {
                        let storage = db.storage.get_slot_storage_entry(slot);
                        if all_slots_shrunk {
                            assert!(storage.is_some());
                        } else {
                            assert!(storage.is_none());
                        }
                    });
                }
            }
        }
    }

    #[test]
    fn test_calc_accounts_to_combine_many_refs() {
        // n storages
        // 1 account each
        // all accounts have 1 ref or all accounts have 2 refs
        solana_logger::setup();

        let alive_bytes_per_slot = 2;

        // pack 2.5 ancient slots into 1 packed slot ideally
        let tuning = PackedAncientStorageTuning {
            ideal_storage_size: NonZeroU64::new(alive_bytes_per_slot * 2 + 1).unwrap(),
            ..default_tuning()
        };
        for many_ref_slots in [IncludeManyRefSlots::Skip, IncludeManyRefSlots::Include] {
            for num_slots in 0..6 {
                for unsorted_slots in [false, true] {
                    for two_refs in [false, true] {
                        let (db, mut storages, _slots, mut infos) =
                            get_sample_storages(num_slots, None);
                        if unsorted_slots {
                            storages = storages.into_iter().rev().collect();
                            infos = infos.into_iter().rev().collect();
                        }

                        let original_results = storages
                            .iter()
                            .map(|store| db.get_unique_accounts_from_storage(store))
                            .collect::<Vec<_>>();
                        if two_refs {
                            original_results.iter().for_each(|results| {
                                results.stored_accounts.iter().for_each(|account| {
                                    db.accounts_index.get_and_then(account.pubkey(), |entry| {
                                        (false, entry.unwrap().addref())
                                    });
                                })
                            });
                        }

                        let original_results = storages
                            .iter()
                            .map(|store| db.get_unique_accounts_from_storage(store))
                            .collect::<Vec<_>>();

                        let mut accounts_per_storage = infos
                            .iter()
                            .zip(original_results.into_iter())
                            .collect::<Vec<_>>();

                        let alive_bytes = num_slots as u64 * alive_bytes_per_slot;
                        let accounts_to_combine = db.calc_accounts_to_combine(
                            &mut accounts_per_storage,
                            &tuning,
                            alive_bytes,
                            many_ref_slots,
                        );
                        let mut expected_accounts_to_combine = num_slots;
                        if two_refs && many_ref_slots == IncludeManyRefSlots::Skip && num_slots > 2
                        {
                            // We require more than 1 target slot. Since all slots have multi refs, we find no slots we can use as target slots.
                            // Thus, nothing can be packed.
                            expected_accounts_to_combine = 0;
                        }
                        (0..accounts_to_combine
                            .target_slots_sorted
                            .len()
                            .saturating_sub(1))
                            .for_each(|i| {
                                let slots = &accounts_to_combine.target_slots_sorted;
                                assert!(slots[i] < slots[i + 1]);
                            });

                        log::debug!("output slots: {:?}, num_slots: {num_slots}, two_refs: {two_refs}, many_refs: {many_ref_slots:?}, expected accounts to combine: {expected_accounts_to_combine}, target slots: {:?}, accounts_to_combine: {}", accounts_to_combine.target_slots_sorted,
                        accounts_to_combine.target_slots_sorted,
                        accounts_to_combine.accounts_to_combine.len(),);
                        assert_eq!(
                            accounts_to_combine.accounts_to_combine.len(),
                            expected_accounts_to_combine,
                            "num_slots: {num_slots}, two_refs: {two_refs}, many_refs: {many_ref_slots:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_calc_accounts_to_combine_simple() {
        // n storages
        // 1 account each
        // all accounts have 1 ref or all accounts have 2 refs
        for many_ref_slots in [IncludeManyRefSlots::Skip, IncludeManyRefSlots::Include] {
            for add_dead_account in [true, false] {
                for method in TestWriteMultipleRefs::iter() {
                    for num_slots in 0..3 {
                        for unsorted_slots in [false, true] {
                            for two_refs in [false, true] {
                                let (db, mut storages, slots, mut infos) =
                                    get_sample_storages(num_slots, None);
                                let slots_vec;
                                if unsorted_slots {
                                    slots_vec = slots.rev().collect::<Vec<_>>();
                                    storages = storages.into_iter().rev().collect();
                                    infos = infos.into_iter().rev().collect();
                                } else {
                                    slots_vec = slots.collect::<Vec<_>>()
                                }

                                let original_results = storages
                                    .iter()
                                    .map(|store| db.get_unique_accounts_from_storage(store))
                                    .collect::<Vec<_>>();
                                if two_refs {
                                    original_results.iter().for_each(|results| {
                                        results.stored_accounts.iter().for_each(|account| {
                                            db.accounts_index
                                                .get_and_then(account.pubkey(), |entry| {
                                                    (false, entry.unwrap().addref())
                                                });
                                        })
                                    });
                                }

                                if add_dead_account {
                                    storages.iter().for_each(|storage| {
                                        let pk = solana_sdk::pubkey::new_rand();
                                        let alive = false;
                                        append_single_account_with_default_hash(
                                            storage,
                                            &pk,
                                            &AccountSharedData::default(),
                                            alive,
                                            Some(&db.accounts_index),
                                        );
                                        assert!(db.accounts_index.purge_exact(
                                            &pk,
                                            &[storage.slot()]
                                                .into_iter()
                                                .collect::<std::collections::HashSet<Slot>>(),
                                            &mut Vec::default()
                                        ));
                                    });
                                }
                                let original_results = storages
                                    .iter()
                                    .map(|store| db.get_unique_accounts_from_storage(store))
                                    .collect::<Vec<_>>();

                                let mut accounts_per_storage = infos
                                    .iter()
                                    .zip(original_results.into_iter())
                                    .collect::<Vec<_>>();

                                let alive_bytes = num_slots;
                                let accounts_to_combine = db.calc_accounts_to_combine(
                                    &mut accounts_per_storage,
                                    &default_tuning(),
                                    alive_bytes as u64,
                                    many_ref_slots,
                                );
                                assert_eq!(
                                    accounts_to_combine.accounts_to_combine.len(),
                                    // if we are only trying to pack a single slot of multi-refs, it will succeed
                                    if !two_refs || many_ref_slots == IncludeManyRefSlots::Include || num_slots == 1 {num_slots} else {0},
                                    "method: {method:?}, num_slots: {num_slots}, two_refs: {two_refs}, many_refs: {many_ref_slots:?}"
                                );

                                if add_dead_account {
                                    assert!(!accounts_to_combine
                                        .accounts_to_combine
                                        .iter()
                                        .any(|a| a.unrefed_pubkeys.is_empty()));
                                }
                                // all accounts should be in one_ref and all slots are available as target slots
                                assert_eq!(
                                    accounts_to_combine.target_slots_sorted,
                                    if !two_refs
                                        || many_ref_slots == IncludeManyRefSlots::Include
                                        || num_slots == 1
                                    {
                                        if unsorted_slots {
                                            slots_vec.iter().cloned().rev().collect::<Vec<_>>()
                                        } else {
                                            slots_vec.clone()
                                        }
                                    } else {
                                        vec![]
                                    },
                                );
                                assert!(accounts_to_combine.accounts_keep_slots.is_empty());
                                assert!(accounts_to_combine.accounts_to_combine.iter().all(
                                    |shrink_collect| shrink_collect
                                        .alive_accounts
                                        .many_refs_old_alive
                                        .accounts
                                        .is_empty()
                                ));
                                if two_refs {
                                    assert!(accounts_to_combine.accounts_to_combine.iter().all(
                                        |shrink_collect| shrink_collect
                                            .alive_accounts
                                            .one_ref
                                            .accounts
                                            .is_empty()
                                    ));
                                    assert!(accounts_to_combine.accounts_to_combine.iter().all(
                                        |shrink_collect| !shrink_collect
                                            .alive_accounts
                                            .many_refs_this_is_newest_alive
                                            .accounts
                                            .is_empty()
                                    ));
                                } else {
                                    assert!(accounts_to_combine.accounts_to_combine.iter().all(
                                        |shrink_collect| !shrink_collect
                                            .alive_accounts
                                            .one_ref
                                            .accounts
                                            .is_empty()
                                    ));
                                    assert!(accounts_to_combine.accounts_to_combine.iter().all(
                                        |shrink_collect| shrink_collect
                                            .alive_accounts
                                            .many_refs_this_is_newest_alive
                                            .accounts
                                            .is_empty()
                                    ));
                                }

                                // test write_ancient_accounts_to_same_slot_multiple_refs since we built interesting 'AccountsToCombine'
                                let write_ancient_accounts = match method {
                                    TestWriteMultipleRefs::MultipleRefs => {
                                        let mut write_ancient_accounts =
                                            WriteAncientAccounts::default();
                                        db.write_ancient_accounts_to_same_slot_multiple_refs(
                                            accounts_to_combine.accounts_keep_slots.values(),
                                            &mut write_ancient_accounts,
                                        );
                                        write_ancient_accounts
                                    }
                                    TestWriteMultipleRefs::PackedStorages => {
                                        let packed_contents = Vec::default();
                                        db.write_packed_storages(
                                            &accounts_to_combine,
                                            packed_contents,
                                        )
                                    }
                                };

                                assert!(write_ancient_accounts.shrinks_in_progress.is_empty());
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_calc_accounts_to_combine_older_dup() {
        // looking at 1 storage
        // with 2 accounts
        // 1 with 1 ref
        // 1 with 2 refs (and the other ref is from a newer slot)
        // So, the other alive ref will cause the account with 2 refs to be put into many_refs_old_alive and then accounts_keep_slots
        for method in TestWriteMultipleRefs::iter() {
            let num_slots = 1;
            // creating 1 more sample slot/storage, but effectively act like 1 slot
            let (db, mut storages, slots, infos) = get_sample_storages(num_slots + 1, None);
            let slots = slots.start..slots.start + 1;
            let storage = storages.first().unwrap().clone();
            let ignored_storage = storages.pop().unwrap();
            let original_results = storages
                .iter()
                .map(|store| db.get_unique_accounts_from_storage(store))
                .collect::<Vec<_>>();
            let pk_with_1_ref = solana_sdk::pubkey::new_rand();
            let slot1 = slots.start;
            let account_with_2_refs = original_results
                .first()
                .unwrap()
                .stored_accounts
                .first()
                .unwrap();
            let account_shared_data_with_2_refs =
                get_account_from_account_from_storage(account_with_2_refs, &db, slot1);
            let pk_with_2_refs = account_with_2_refs.pubkey();
            let mut account_with_1_ref = account_shared_data_with_2_refs.clone();
            account_with_1_ref.checked_add_lamports(1).unwrap();
            append_single_account_with_default_hash(
                &storage,
                &pk_with_1_ref,
                &account_with_1_ref,
                true,
                Some(&db.accounts_index),
            );
            // add the account with 2 refs into the storage we're ignoring.
            // The storage we're ignoring has a higher slot.
            // The index entry for pk_with_2_refs will have both slots in it.
            // The slot of `storage` is lower than the slot of `ignored_storage`.
            // But, both are 'alive', aka in the index.
            append_single_account_with_default_hash(
                &ignored_storage,
                pk_with_2_refs,
                &account_shared_data_with_2_refs,
                true,
                Some(&db.accounts_index),
            );

            // update to get both accounts in the storage
            let original_results = storages
                .iter()
                .map(|store| db.get_unique_accounts_from_storage(store))
                .collect::<Vec<_>>();
            assert_eq!(original_results.first().unwrap().stored_accounts.len(), 2);
            let mut accounts_per_storage = infos
                .iter()
                .zip(original_results.into_iter())
                .collect::<Vec<_>>();

            let alive_bytes = 1000; // just something
            let accounts_to_combine = db.calc_accounts_to_combine(
                &mut accounts_per_storage,
                &default_tuning(),
                alive_bytes,
                IncludeManyRefSlots::Include,
            );
            let slots_vec = slots.collect::<Vec<_>>();
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), num_slots);
            // all accounts should be in many_refs
            let mut accounts_keep = accounts_to_combine
                .accounts_keep_slots
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            accounts_keep.sort_unstable();
            assert_eq!(accounts_keep, slots_vec);
            assert!(accounts_to_combine.target_slots_sorted.is_empty());
            assert_eq!(accounts_to_combine.accounts_keep_slots.len(), num_slots);
            assert_eq!(
                accounts_to_combine
                    .accounts_keep_slots
                    .get(&slot1)
                    .unwrap()
                    .accounts
                    .iter()
                    .map(|meta| meta.pubkey())
                    .collect::<Vec<_>>(),
                vec![pk_with_2_refs]
            );
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), 1);
            let one_ref_accounts = &accounts_to_combine
                .accounts_to_combine
                .first()
                .unwrap()
                .alive_accounts
                .one_ref
                .accounts;
            let one_ref_accounts_account_shared_data = one_ref_accounts
                .iter()
                .map(|account| get_account_from_account_from_storage(account, &db, slot1))
                .collect::<Vec<_>>();

            assert_eq!(
                one_ref_accounts
                    .iter()
                    .map(|meta| meta.pubkey())
                    .collect::<Vec<_>>(),
                vec![&pk_with_1_ref]
            );
            assert_eq!(
                one_ref_accounts_account_shared_data
                    .iter()
                    .map(|meta| meta.to_account_shared_data())
                    .collect::<Vec<_>>(),
                vec![account_with_1_ref]
            );
            assert!(accounts_to_combine
                .accounts_to_combine
                .iter()
                .all(|shrink_collect| shrink_collect
                    .alive_accounts
                    .many_refs_this_is_newest_alive
                    .accounts
                    .is_empty()));
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), 1);

            assert!(accounts_to_combine
                .accounts_to_combine
                .iter()
                .all(|shrink_collect| shrink_collect
                    .alive_accounts
                    .many_refs_old_alive
                    .accounts
                    .is_empty()));

            // test write_ancient_accounts_to_same_slot_multiple_refs since we built interesting 'AccountsToCombine'
            let write_ancient_accounts = match method {
                TestWriteMultipleRefs::MultipleRefs => {
                    let mut write_ancient_accounts = WriteAncientAccounts::default();
                    db.write_ancient_accounts_to_same_slot_multiple_refs(
                        accounts_to_combine.accounts_keep_slots.values(),
                        &mut write_ancient_accounts,
                    );
                    write_ancient_accounts
                }
                TestWriteMultipleRefs::PackedStorages => {
                    let packed_contents = Vec::default();
                    db.write_packed_storages(&accounts_to_combine, packed_contents)
                }
            };
            assert_eq!(write_ancient_accounts.shrinks_in_progress.len(), num_slots);
            let mut shrinks_in_progress = write_ancient_accounts
                .shrinks_in_progress
                .iter()
                .collect::<Vec<_>>();
            shrinks_in_progress.sort_unstable_by(|a, b| a.0.cmp(b.0));
            assert_eq!(
                shrinks_in_progress
                    .iter()
                    .map(|(slot, _)| **slot)
                    .collect::<Vec<_>>(),
                slots_vec
            );
            assert_eq!(
                shrinks_in_progress
                    .iter()
                    .map(|(_, shrink_in_progress)| shrink_in_progress.old_storage().append_vec_id())
                    .collect::<Vec<_>>(),
                storages
                    .iter()
                    .map(|storage| storage.append_vec_id())
                    .collect::<Vec<_>>()
            );
            // assert that we wrote the 2_ref account to the newly shrunk append vec
            let shrink_in_progress = shrinks_in_progress.first().unwrap().1;
            let mut count = 0;
            shrink_in_progress
                .new_storage()
                .accounts
                .scan_accounts(|_| {
                    count += 1;
                });
            assert_eq!(count, 1);
            let account = shrink_in_progress
                .new_storage()
                .accounts
                .get_stored_account_meta_callback(0, |account| {
                    assert_eq!(account.pubkey(), pk_with_2_refs);
                    account.to_account_shared_data()
                })
                .unwrap();
            assert_eq!(account, account_shared_data_with_2_refs);
        }
    }

    #[test]
    fn test_calc_accounts_to_combine_opposite() {
        solana_logger::setup();
        // 1 storage
        // 2 accounts
        // 1 with 1 ref
        // 1 with 2 refs, with the idea that the other ref is from an older slot, so this one is the newer index entry
        // The result will be that the account, even though it has refcount > 1, can be moved to a newer slot.
        for method in TestWriteMultipleRefs::iter() {
            let num_slots = 1;
            let (db, storages, slots, infos) = get_sample_storages(num_slots, None);
            let original_results = storages
                .iter()
                .map(|store| db.get_unique_accounts_from_storage(store))
                .collect::<Vec<_>>();
            let storage = storages.first().unwrap().clone();
            let pk_with_1_ref = solana_sdk::pubkey::new_rand();
            let slot1 = slots.start;
            let account_with_2_refs = original_results
                .first()
                .unwrap()
                .stored_accounts
                .first()
                .unwrap();
            let account_shared_data_with_2_refs =
                get_account_from_account_from_storage(account_with_2_refs, &db, slot1);
            let pk_with_2_refs = account_with_2_refs.pubkey();
            let mut account_with_1_ref = account_shared_data_with_2_refs.clone();
            _ = account_with_1_ref.checked_add_lamports(1);
            append_single_account_with_default_hash(
                &storage,
                &pk_with_1_ref,
                &account_with_1_ref,
                true,
                Some(&db.accounts_index),
            );
            original_results.iter().for_each(|results| {
                results.stored_accounts.iter().for_each(|account| {
                    db.accounts_index
                        .get_and_then(account.pubkey(), |entry| (true, entry.unwrap().addref()));
                })
            });

            // update to get both accounts in the storage
            let original_results = storages
                .iter()
                .map(|store| db.get_unique_accounts_from_storage(store))
                .collect::<Vec<_>>();
            assert_eq!(original_results.first().unwrap().stored_accounts.len(), 2);
            let mut accounts_per_storage = infos
                .iter()
                .zip(original_results.into_iter())
                .collect::<Vec<_>>();

            let alive_bytes = 0; // just something
            let accounts_to_combine = db.calc_accounts_to_combine(
                &mut accounts_per_storage,
                &default_tuning(),
                alive_bytes,
                IncludeManyRefSlots::Include,
            );
            let slots_vec = slots.collect::<Vec<_>>();
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), num_slots);
            // all accounts should be in many_refs_this_is_newest_alive
            let mut accounts_keep = accounts_to_combine
                .accounts_keep_slots
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            accounts_keep.sort_unstable();
            assert_eq!(accounts_to_combine.target_slots_sorted, slots_vec);
            assert!(accounts_keep.is_empty());
            assert!(!accounts_to_combine.target_slots_sorted.is_empty());
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), num_slots);
            assert_eq!(
                accounts_to_combine
                    .accounts_to_combine
                    .first()
                    .unwrap()
                    .alive_accounts
                    .many_refs_this_is_newest_alive
                    .accounts
                    .iter()
                    .map(|meta| meta.pubkey())
                    .collect::<Vec<_>>(),
                vec![pk_with_2_refs]
            );
            assert_eq!(accounts_to_combine.accounts_to_combine.len(), 1);
            let one_ref_accounts = &accounts_to_combine
                .accounts_to_combine
                .first()
                .unwrap()
                .alive_accounts
                .one_ref
                .accounts;
            let one_ref_accounts_account_shared_data = one_ref_accounts
                .iter()
                .map(|account| get_account_from_account_from_storage(account, &db, slot1))
                .collect::<Vec<_>>();
            assert_eq!(
                one_ref_accounts
                    .iter()
                    .map(|meta| meta.pubkey())
                    .collect::<Vec<_>>(),
                vec![&pk_with_1_ref]
            );
            assert_eq!(
                one_ref_accounts_account_shared_data
                    .iter()
                    .map(|meta| meta.to_account_shared_data())
                    .collect::<Vec<_>>(),
                vec![account_with_1_ref]
            );
            assert!(accounts_to_combine
                .accounts_to_combine
                .iter()
                .all(|shrink_collect| !shrink_collect
                    .alive_accounts
                    .many_refs_this_is_newest_alive
                    .accounts
                    .is_empty()));

            // test write_ancient_accounts_to_same_slot_multiple_refs since we built interesting 'AccountsToCombine'
            let write_ancient_accounts = match method {
                TestWriteMultipleRefs::MultipleRefs => {
                    let mut write_ancient_accounts = WriteAncientAccounts::default();
                    db.write_ancient_accounts_to_same_slot_multiple_refs(
                        accounts_to_combine.accounts_keep_slots.values(),
                        &mut write_ancient_accounts,
                    );
                    write_ancient_accounts
                }
                TestWriteMultipleRefs::PackedStorages => {
                    let packed_contents = Vec::default();
                    db.write_packed_storages(&accounts_to_combine, packed_contents)
                }
            };
            assert!(write_ancient_accounts.shrinks_in_progress.is_empty());
            // assert that we wrote the 2_ref account (and the 1 ref account) to the newly shrunk append vec
            let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
            let accounts_shrunk_same_slot = storage
                .accounts
                .get_stored_account_meta_callback(0, |account| {
                    (*account.pubkey(), account.to_account_shared_data())
                })
                .unwrap();
            let mut count = 0;
            storage.accounts.scan_accounts(|_| {
                count += 1;
            });
            assert_eq!(count, 2);
            assert_eq!(accounts_shrunk_same_slot.0, *pk_with_2_refs);
            assert_eq!(accounts_shrunk_same_slot.1, account_shared_data_with_2_refs);
        }
    }

    #[test]
    fn test_get_unique_accounts_from_storage_for_combining_ancient_slots() {
        for num_slots in 0..3 {
            for reverse in [false, true] {
                let (db, storages, slots, mut infos) = get_sample_storages(num_slots, None);
                let original_results = storages
                    .iter()
                    .map(|store| db.get_unique_accounts_from_storage(store))
                    .collect::<Vec<_>>();
                if reverse {
                    // reverse the contents for further testing
                    infos = infos.into_iter().rev().collect();
                }
                let results =
                    db.get_unique_accounts_from_storage_for_combining_ancient_slots(&infos);

                let all_accounts = get_all_accounts(&db, slots.clone());
                assert_eq!(all_accounts.len(), num_slots);

                compare_all_vec_accounts(
                    original_results.iter(),
                    results.iter().map(|(_, accounts)| accounts),
                    &db,
                    slots.start,
                );
                compare_all_accounts(
                    &all_accounts,
                    &unique_to_accounts(
                        results.iter().map(|(_, accounts)| accounts),
                        &db,
                        slots.start,
                    ),
                );

                let map = |info: &SlotInfo| {
                    (
                        info.storage.append_vec_id(),
                        info.slot,
                        info.capacity,
                        info.alive_bytes,
                        info.should_shrink,
                    )
                };
                assert_eq!(
                    infos.iter().map(map).collect::<Vec<_>>(),
                    results
                        .into_iter()
                        .map(|(info, _)| map(info))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn test_accounts_to_store_simple() {
        let map = vec![];
        let slot = 1;
        let accounts_to_store = AccountsToStore::new(0, &map, 0, slot);
        for selector in [StorageSelector::Primary, StorageSelector::Overflow] {
            let accounts = accounts_to_store.get(selector);
            assert!(accounts.is_empty());
        }
        assert!(!accounts_to_store.has_overflow());
    }

    #[test]
    fn test_accounts_to_store_more() {
        let pubkey = Pubkey::from([1; 32]);
        let account_size = 3;

        let account = AccountSharedData::default();

        let account_meta = AccountMeta {
            lamports: 1,
            owner: Pubkey::from([2; 32]),
            executable: false,
            rent_epoch: 0,
        };
        let offset = 3 * std::mem::size_of::<u64>();
        let hash = AccountHash(Hash::new(&[2; 32]));
        let stored_meta = StoredMeta {
            // global write version
            write_version_obsolete: 0,
            // key for the account
            pubkey,
            data_len: 43,
        };
        let account = StoredAccountMeta::AppendVec(AppendVecStoredAccountMeta {
            meta: &stored_meta,
            // account data
            account_meta: &account_meta,
            data: account.data(),
            offset,
            stored_size: account_size,
            hash: &hash,
        });
        let map = [&account];
        let map_accounts_from_storage = build_accounts_from_storage(map.iter().copied());
        for (selector, available_bytes) in [
            (StorageSelector::Primary, account_size),
            (StorageSelector::Overflow, account_size - 1),
        ] {
            let slot = 1;
            let alive_total_bytes = account_size;
            let temp = map_accounts_from_storage.iter().collect::<Vec<_>>();
            let accounts_to_store =
                AccountsToStore::new(available_bytes as u64, &temp, alive_total_bytes, slot);
            let accounts = accounts_to_store.get(selector);
            assert_eq!(
                accounts.to_vec(),
                map_accounts_from_storage.iter().collect::<Vec<_>>(),
                "mismatch"
            );
            let accounts = accounts_to_store.get(get_opposite(&selector));
            assert_eq!(
                selector == StorageSelector::Overflow,
                accounts_to_store.has_overflow()
            );
            assert!(accounts.is_empty());

            assert_eq!(accounts_to_store.get_bytes(selector), account_size);
            assert_eq!(accounts_to_store.get_bytes(get_opposite(&selector)), 0);
        }
    }
    fn get_opposite(selector: &StorageSelector) -> StorageSelector {
        match selector {
            StorageSelector::Overflow => StorageSelector::Primary,
            StorageSelector::Primary => StorageSelector::Overflow,
        }
    }

    #[test]
    fn test_get_ancient_append_vec_capacity() {
        assert_eq!(get_ancient_append_vec_capacity(), 128 * 1024 * 1024);
    }

    #[test]
    fn test_is_ancient() {
        for (size, expected_ancient) in [
            (get_ancient_append_vec_capacity() + 1, true),
            (get_ancient_append_vec_capacity(), true),
            (get_ancient_append_vec_capacity() - 1, false),
        ] {
            let tf = crate::append_vec::test_utils::get_append_vec_path("test_is_ancient");
            let (_temp_dirs, _paths) = get_temp_accounts_paths(1).unwrap();
            let av = AccountsFile::AppendVec(AppendVec::new(&tf.path, true, size as usize));

            assert_eq!(expected_ancient, is_ancient(&av));
        }
    }

    fn get_one_packed_ancient_append_vec_and_others(
        alive: bool,
        num_normal_slots: usize,
    ) -> (AccountsDb, Slot) {
        let (db, slot1) = create_db_with_storages_and_index(alive, num_normal_slots + 1, None);
        let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
        let created_accounts = db.get_unique_accounts_from_storage(&storage);

        db.combine_ancient_slots_packed(vec![slot1], CAN_RANDOMLY_SHRINK_FALSE);
        assert!(db.storage.get_slot_storage_entry(slot1).is_some());
        let after_store = db.storage.get_slot_storage_entry(slot1).unwrap();
        let GetUniqueAccountsResult {
            stored_accounts: after_stored_accounts,
            capacity: after_capacity,
            ..
        } = db.get_unique_accounts_from_storage(&after_store);
        assert_eq!(created_accounts.capacity, after_capacity);
        assert_eq!(created_accounts.stored_accounts.len(), 1);
        // always 1 account: either we leave the append vec alone if it is all dead
        // or we create a new one and copy into it if account is alive
        assert_eq!(after_stored_accounts.len(), 1);
        (db, slot1)
    }

    fn assert_storage_info(info: &SlotInfo, storage: &AccountStorageEntry, should_shrink: bool) {
        assert_eq!(storage.append_vec_id(), info.storage.append_vec_id());
        assert_eq!(storage.slot(), info.slot);
        assert_eq!(storage.capacity(), info.capacity);
        assert_eq!(storage.alive_bytes(), info.alive_bytes as usize);
        assert_eq!(should_shrink, info.should_shrink);
    }

    #[derive(EnumIter, Debug, PartialEq, Eq)]
    enum TestCollectInfo {
        CollectSortFilterInfo,
        CalcAncientSlotInfo,
        Add,
    }

    #[test]
    fn test_calc_ancient_slot_info_one_alive_only() {
        let can_randomly_shrink = false;
        let alive = true;
        let slots = 1;
        for method in TestCollectInfo::iter() {
            // 1_040_000 is big enough relative to page size to cause shrink ratio to be triggered
            for data_size in [None, Some(1_040_000)] {
                let (db, slot1) = create_db_with_storages_and_index(alive, slots, data_size);
                let mut infos = AncientSlotInfos::default();
                let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
                let alive_bytes_expected = storage.alive_bytes();
                let high_slot = false;
                match method {
                    TestCollectInfo::Add => {
                        // test lower level 'add'
                        infos.add(
                            slot1,
                            Arc::clone(&storage),
                            can_randomly_shrink,
                            NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                            high_slot,
                        );
                    }
                    TestCollectInfo::CalcAncientSlotInfo => {
                        infos = db.calc_ancient_slot_info(
                            vec![slot1],
                            can_randomly_shrink,
                            NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                        );
                    }
                    TestCollectInfo::CollectSortFilterInfo => {
                        let tuning = PackedAncientStorageTuning {
                            percent_of_alive_shrunk_data: 100,
                            max_ancient_slots: 0,
                            // irrelevant for what this test is trying to test, but necessary to avoid minimums
                            ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity())
                                .unwrap(),
                            can_randomly_shrink,
                            ..default_tuning()
                        };
                        infos = db.collect_sort_filter_ancient_slots(vec![slot1], &tuning);
                    }
                }
                assert_eq!(infos.all_infos.len(), 1, "{method:?}");
                let should_shrink = data_size.is_none();
                assert_storage_info(infos.all_infos.first().unwrap(), &storage, should_shrink);
                if should_shrink {
                    // data size is so small compared to min aligned file size that the storage is marked as should_shrink
                    assert_eq!(
                        infos.shrink_indexes,
                        if !matches!(method, TestCollectInfo::CollectSortFilterInfo) {
                            vec![0]
                        } else {
                            Vec::default()
                        }
                    );
                    assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected as u64);
                    assert_eq!(
                        infos.total_alive_bytes_shrink.0,
                        alive_bytes_expected as u64
                    );
                } else {
                    assert!(infos.shrink_indexes.is_empty());
                    assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected as u64);
                    assert_eq!(infos.total_alive_bytes_shrink.0, 0);
                }
            }
        }
    }

    #[test]
    fn test_calc_ancient_slot_info_one_dead() {
        let can_randomly_shrink = false;
        let alive = false;
        let slots = 1;
        for call_add in [false, true] {
            let (db, slot1) = create_db_with_storages_and_index(alive, slots, None);
            let mut infos = AncientSlotInfos::default();
            let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
            let high_slot = false;
            if call_add {
                infos.add(
                    slot1,
                    Arc::clone(&storage),
                    can_randomly_shrink,
                    NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                    high_slot,
                );
            } else {
                infos = db.calc_ancient_slot_info(
                    vec![slot1],
                    can_randomly_shrink,
                    NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                );
            }
            assert!(infos.all_infos.is_empty());
            assert!(infos.shrink_indexes.is_empty());
            assert_eq!(infos.total_alive_bytes.0, 0);
            assert_eq!(infos.total_alive_bytes_shrink.0, 0);
        }
    }

    #[test]
    fn test_calc_ancient_slot_info_several() {
        let can_randomly_shrink = false;
        for alive in [true, false] {
            for slots in 0..4 {
                // 1_040_000 is big enough relative to page size to cause shrink ratio to be triggered
                for data_size in [None, Some(1_040_000)] {
                    let (db, slot1) = create_db_with_storages_and_index(alive, slots, data_size);
                    let slot_vec = (slot1..(slot1 + slots as Slot)).collect::<Vec<_>>();
                    let storages = slot_vec
                        .iter()
                        .map(|slot| db.storage.get_slot_storage_entry(*slot).unwrap())
                        .collect::<Vec<_>>();
                    let alive_bytes_expected = storages
                        .iter()
                        .map(|storage| storage.alive_bytes() as u64)
                        .sum::<u64>();
                    let infos = db.calc_ancient_slot_info(
                        slot_vec.clone(),
                        can_randomly_shrink,
                        NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                    );
                    if !alive {
                        assert!(infos.all_infos.is_empty());
                        assert!(infos.shrink_indexes.is_empty());
                        assert_eq!(infos.total_alive_bytes.0, 0);
                        assert_eq!(infos.total_alive_bytes_shrink.0, 0);
                    } else {
                        assert_eq!(infos.all_infos.len(), slots);
                        let should_shrink = data_size.is_none();
                        storages
                            .iter()
                            .zip(infos.all_infos.iter())
                            .for_each(|(storage, info)| {
                                assert_storage_info(info, storage, should_shrink);
                            });
                        if should_shrink {
                            // data size is so small compared to min aligned file size that the storage is marked as should_shrink
                            assert_eq!(
                                infos.shrink_indexes,
                                slot_vec
                                    .iter()
                                    .enumerate()
                                    .map(|(i, _)| i)
                                    .collect::<Vec<_>>()
                            );
                            assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected);
                            assert_eq!(infos.total_alive_bytes_shrink.0, alive_bytes_expected);
                        } else {
                            assert!(infos.shrink_indexes.is_empty());
                            assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected);
                            assert_eq!(infos.total_alive_bytes_shrink.0, 0);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_calc_ancient_slot_info_one_alive_one_dead() {
        let can_randomly_shrink = false;
        for method in TestCollectInfo::iter() {
            for slot1_is_alive in [false, true] {
                let alives = [false /*dummy*/, slot1_is_alive, !slot1_is_alive];
                let slots = 2;
                // 1_040_000 is big enough relative to page size to cause shrink ratio to be triggered
                for data_size in [None, Some(1_040_000)] {
                    let (db, slot1) =
                        create_db_with_storages_and_index(true /*alive*/, slots, data_size);
                    assert_eq!(slot1, 1); // make sure index into alives will be correct
                    assert_eq!(alives[slot1 as usize], slot1_is_alive);
                    let slot_vec = (slot1..(slot1 + slots as Slot)).collect::<Vec<_>>();
                    let storages = slot_vec
                        .iter()
                        .map(|slot| db.storage.get_slot_storage_entry(*slot).unwrap())
                        .collect::<Vec<_>>();
                    storages.iter().for_each(|storage| {
                        let slot = storage.slot();
                        let alive = alives[slot as usize];
                        if !alive {
                            // make this storage not alive
                            remove_account_for_tests(
                                storage,
                                storage.written_bytes() as usize,
                                false,
                            );
                        }
                    });
                    let alive_storages = storages
                        .iter()
                        .filter(|storage| alives[storage.slot() as usize])
                        .collect::<Vec<_>>();
                    let alive_bytes_expected = alive_storages
                        .iter()
                        .map(|storage| storage.alive_bytes() as u64)
                        .sum::<u64>();

                    let infos = match method {
                        TestCollectInfo::CalcAncientSlotInfo => db.calc_ancient_slot_info(
                            slot_vec.clone(),
                            can_randomly_shrink,
                            NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                        ),
                        TestCollectInfo::Add => {
                            continue; // unsupportable
                        }
                        TestCollectInfo::CollectSortFilterInfo => {
                            let tuning = PackedAncientStorageTuning {
                                percent_of_alive_shrunk_data: 100,
                                max_ancient_slots: 0,
                                // irrelevant
                                ideal_storage_size: NonZeroU64::new(
                                    get_ancient_append_vec_capacity(),
                                )
                                .unwrap(),
                                can_randomly_shrink,
                                ..default_tuning()
                            };
                            db.collect_sort_filter_ancient_slots(slot_vec.clone(), &tuning)
                        }
                    };
                    assert_eq!(infos.all_infos.len(), 1, "method: {method:?}");
                    let should_shrink = data_size.is_none();
                    alive_storages.iter().zip(infos.all_infos.iter()).for_each(
                        |(storage, info)| {
                            assert_storage_info(info, storage, should_shrink);
                        },
                    );
                    if should_shrink {
                        // data size is so small compared to min aligned file size that the storage is marked as should_shrink
                        assert_eq!(
                            infos.shrink_indexes,
                            if !matches!(method, TestCollectInfo::CollectSortFilterInfo) {
                                vec![0]
                            } else {
                                Vec::default()
                            }
                        );
                        assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected);
                        assert_eq!(infos.total_alive_bytes_shrink.0, alive_bytes_expected);
                    } else {
                        assert!(infos.shrink_indexes.is_empty());
                        assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected);
                        assert_eq!(infos.total_alive_bytes_shrink.0, 0);
                    }
                }
            }
        }
    }

    fn create_test_infos(count: usize) -> AncientSlotInfos {
        let (db, slot1) = create_db_with_storages_and_index(true /*alive*/, 1, None);
        let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
        AncientSlotInfos {
            all_infos: (0..count)
                .map(|index| SlotInfo {
                    storage: Arc::clone(&storage),
                    slot: index as Slot,
                    capacity: 1,
                    alive_bytes: 1,
                    should_shrink: false,
                    is_high_slot: false,
                })
                .collect(),
            shrink_indexes: (0..count).collect(),
            ..AncientSlotInfos::default()
        }
    }

    #[derive(EnumIter, Debug, PartialEq, Eq)]
    enum TestSmallestCapacity {
        FilterAncientSlots,
        FilterBySmallestCapacity,
    }

    #[test]
    fn test_filter_by_smallest_capacity_empty() {
        for method in TestSmallestCapacity::iter() {
            for max_storages in 1..3 {
                // requesting N max storage, has 1 storage, N >= 1 so nothing to do
                let ideal_storage_size_large = get_ancient_append_vec_capacity();
                let mut infos = create_test_infos(1);
                let tuning = PackedAncientStorageTuning {
                    max_ancient_slots: max_storages,
                    ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                    // irrelevant since we clear 'shrink_indexes'
                    percent_of_alive_shrunk_data: 0,
                    can_randomly_shrink: false,
                    ..default_tuning()
                };
                match method {
                    TestSmallestCapacity::FilterAncientSlots => {
                        infos.shrink_indexes.clear();
                        infos.filter_ancient_slots(&tuning, &ShrinkAncientStats::default());
                    }
                    TestSmallestCapacity::FilterBySmallestCapacity => {
                        infos.filter_by_smallest_capacity(&tuning, &ShrinkAncientStats::default());
                    }
                }
                assert!(infos.all_infos.is_empty());
            }
        }
    }

    #[test]
    fn test_filter_by_smallest_capacity_sort() {
        // max is 6
        // 7 storages
        // storage[last] is big enough to cause us to need another storage
        // so, storage[0..=4] can be combined into 1, resulting in 3 remaining storages, which is
        // the goal, so we only have to combine the first 5 to hit the goal
        for method in TestSmallestCapacity::iter() {
            let ideal_storage_size_large = get_ancient_append_vec_capacity();
            for reorder in [false, true] {
                let mut infos = create_test_infos(7);
                infos
                    .all_infos
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, info)| info.capacity = 1 + i as u64);
                if reorder {
                    infos.all_infos.last_mut().unwrap().capacity = 0; // sort to beginning
                }
                infos.all_infos.last_mut().unwrap().alive_bytes = ideal_storage_size_large;
                // if we use max_storages = 3 or 4, then the low limit is 1 or 2. To get below 2 requires a result of 1, which packs everyone.
                // This isn't what we want for this test. So, we make max_storages big enough that we can get to something reasonable (like 3)
                // for a low mark.
                let max_storages = 6;

                let tuning = PackedAncientStorageTuning {
                    max_ancient_slots: max_storages,
                    ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                    // irrelevant since we clear 'shrink_indexes'
                    percent_of_alive_shrunk_data: 0,
                    can_randomly_shrink: false,
                    ..default_tuning()
                };
                match method {
                    TestSmallestCapacity::FilterBySmallestCapacity => {
                        infos.filter_by_smallest_capacity(&tuning, &ShrinkAncientStats::default());
                    }
                    TestSmallestCapacity::FilterAncientSlots => {
                        infos.shrink_indexes.clear();
                        infos.filter_ancient_slots(&tuning, &ShrinkAncientStats::default());
                    }
                }
                assert_eq!(
                    infos
                        .all_infos
                        .iter()
                        .map(|info| info.slot)
                        .collect::<Vec<_>>(),
                    if reorder {
                        vec![6, 0, 1, 2, 3, 4]
                    } else {
                        vec![0, 1, 2, 3, 4]
                    },
                    "reorder: {reorder}, method: {method:?}"
                );
            }
        }
    }

    /// Test that we always include the high slots when filtering which ancient infos to pack
    ///
    /// If we have *more* high slots than max resulting storages set in the tuning parameters,
    /// we should still have all the high slots after calling `filter_by_smallest_capacity().
    #[test]
    fn test_filter_by_smallest_capacity_high_slot_more() {
        let tuning = default_tuning();

        // Ensure we have more storages with high slots than the 'max resulting storages'.
        let num_high_slots = tuning.max_resulting_storages.get() * 2;
        let num_ancient_storages = num_high_slots * 3;
        let mut infos = create_test_infos(num_ancient_storages as usize);
        infos
            .all_infos
            .sort_unstable_by_key(|slot_info| slot_info.slot);
        infos
            .all_infos
            .iter_mut()
            .rev()
            .take(num_high_slots as usize)
            .for_each(|slot_info| {
                slot_info.is_high_slot = true;
            });
        let slots_expected: Vec<_> = infos
            .all_infos
            .iter()
            .filter_map(|slot_info| slot_info.is_high_slot.then_some(slot_info.slot))
            .collect();

        // shuffle the infos so they actually need to be sorted
        infos.all_infos.shuffle(&mut thread_rng());
        infos.filter_by_smallest_capacity(&tuning, &ShrinkAncientStats::default());

        infos
            .all_infos
            .sort_unstable_by_key(|slot_info| slot_info.slot);
        let slots_actual: Vec<_> = infos
            .all_infos
            .iter()
            .map(|slot_info| slot_info.slot)
            .collect();
        assert_eq!(infos.all_infos.len() as u64, num_high_slots);
        assert_eq!(slots_actual, slots_expected);
    }

    /// Test that we always include the high slots when filtering which ancient infos to pack
    ///
    /// If we have *less* high slots than max resulting storages set in the tuning parameters,
    /// we should still have all the high slots after calling `filter_by_smallest_capacity().
    #[test]
    fn test_filter_by_smallest_capacity_high_slot_less() {
        let tuning = default_tuning();

        // Ensure we have less storages with high slots than the 'max resulting storages'.
        let num_high_slots = tuning.max_resulting_storages.get() / 2;
        let num_ancient_storages = num_high_slots * 5;
        let mut infos = create_test_infos(num_ancient_storages as usize);
        infos
            .all_infos
            .sort_unstable_by_key(|slot_info| slot_info.slot);
        infos
            .all_infos
            .iter_mut()
            .rev()
            .take(num_high_slots as usize)
            .for_each(|slot_info| {
                slot_info.is_high_slot = true;
            });
        let high_slots: Vec<_> = infos
            .all_infos
            .iter()
            .filter_map(|slot_info| slot_info.is_high_slot.then_some(slot_info.slot))
            .collect();

        // shuffle the infos so they actually need to be sorted
        infos.all_infos.shuffle(&mut thread_rng());
        infos.filter_by_smallest_capacity(&tuning, &ShrinkAncientStats::default());

        infos
            .all_infos
            .sort_unstable_by_key(|slot_info| slot_info.slot);
        let slots_actual: HashSet<_> = infos
            .all_infos
            .iter()
            .map(|slot_info| slot_info.slot)
            .collect();
        assert_eq!(
            infos.all_infos.len() as u64,
            tuning.max_resulting_storages.get(),
        );
        assert!(high_slots
            .iter()
            .all(|high_slot| slots_actual.contains(high_slot)));
    }

    fn test(filter: bool, infos: &mut AncientSlotInfos, tuning: &PackedAncientStorageTuning) {
        if filter {
            infos.filter_by_smallest_capacity(tuning, &ShrinkAncientStats::default());
        } else {
            infos.truncate_to_max_storages(tuning, &ShrinkAncientStats::default());
        }
    }

    #[test]
    fn test_truncate_to_max_storages() {
        solana_logger::setup();
        for filter in [false, true] {
            let ideal_storage_size_large = get_ancient_append_vec_capacity();
            let mut infos = create_test_infos(1);
            let max_storages = 1;
            // 1 storage, 1 max, but 1 storage does not fill the entire new combined storage, so truncate nothing
            let tuning = PackedAncientStorageTuning {
                max_ancient_slots: max_storages,
                ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                ..default_tuning()
            };
            test(filter, &mut infos, &tuning);
            assert_eq!(infos.all_infos.len(), usize::from(!filter));

            let mut infos = create_test_infos(1);
            let max_storages = 1;
            let tuning = PackedAncientStorageTuning {
                max_ancient_slots: max_storages,
                ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                ..default_tuning()
            };
            infos.all_infos[0].alive_bytes = ideal_storage_size_large + 1; // too big for 1 ideal storage
                                                                           // 1 storage, 1 max, but 1 overflows the entire new combined storage, so truncate nothing
            test(filter, &mut infos, &tuning);
            assert_eq!(infos.all_infos.len(), usize::from(!filter));

            let mut infos = create_test_infos(1);
            let max_storages = 2;
            let tuning = PackedAncientStorageTuning {
                max_ancient_slots: max_storages,
                ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                ..default_tuning()
            };
            // all truncated because these infos will fit into the # storages
            test(filter, &mut infos, &tuning);

            if filter {
                assert!(infos.all_infos.is_empty());
            } else {
                // no short circuit, so truncate to shrink below low water
                assert_eq!(
                    infos
                        .all_infos
                        .iter()
                        .map(|info| info.slot)
                        .collect::<Vec<_>>(),
                    vec![0]
                );
            }

            let mut infos = create_test_infos(1);
            infos.all_infos[0].alive_bytes = ideal_storage_size_large + 1;
            let max_storages = 2;
            let tuning = PackedAncientStorageTuning {
                max_ancient_slots: max_storages,
                ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                ..default_tuning()
            };

            // none truncated because the one storage calculates to be larger than 1 ideal storage, so we need to
            // combine
            test(filter, &mut infos, &tuning);
            assert_eq!(
                infos
                    .all_infos
                    .iter()
                    .map(|info| info.slot)
                    .collect::<Vec<_>>(),
                if filter { Vec::default() } else { vec![0] }
            );

            // both need to be combined to reach '1'
            let max_storages = 1;
            for ideal_storage_size in [1, 2] {
                let tuning = PackedAncientStorageTuning {
                    max_ancient_slots: max_storages,
                    ideal_storage_size: NonZeroU64::new(ideal_storage_size).unwrap(),
                    ..default_tuning()
                };
                let mut infos = create_test_infos(2);
                test(filter, &mut infos, &tuning);
                assert_eq!(infos.all_infos.len(), 2);
            }

            // max is 4
            // 5 storages
            // storage[4] is big enough to cause us to need another storage
            // so, storage[0..=2] can be combined into 1, resulting in 3 remaining storages, which is
            // the goal, so we only have to combine the first 3 to hit the goal
            let mut infos = create_test_infos(5);
            infos.all_infos[4].alive_bytes = ideal_storage_size_large;
            let max_storages = 4;
            let tuning = PackedAncientStorageTuning {
                max_ancient_slots: max_storages,
                ideal_storage_size: NonZeroU64::new(ideal_storage_size_large).unwrap(),
                ..default_tuning()
            };

            test(filter, &mut infos, &tuning);
            assert_eq!(
                infos
                    .all_infos
                    .iter()
                    .map(|info| info.slot)
                    .collect::<Vec<_>>(),
                vec![0, 1, 2, 3, 4]
            );
        }
    }

    #[test]
    fn test_calc_ancient_slot_info_one_shrink_one_not() {
        let can_randomly_shrink = false;
        for method in TestCollectInfo::iter() {
            for slot1_shrink in [false, true] {
                let shrinks = [false /*dummy*/, slot1_shrink, !slot1_shrink];
                let slots = 2;
                // 1_040_000 is big enough relative to page size to cause shrink ratio to be triggered
                let data_sizes = shrinks
                    .iter()
                    .map(|shrink| (!shrink).then_some(1_040_000))
                    .collect::<Vec<_>>();
                let (db, slot1) =
                    create_db_with_storages_and_index(true /*alive*/, 1, data_sizes[1]);
                let dead_bytes = 184; // constant based on None data size
                create_storages_and_update_index(
                    &db,
                    None,
                    slot1 + 1,
                    1,
                    true,
                    data_sizes[(slot1 + 1) as usize],
                );

                assert_eq!(slot1, 1); // make sure index into shrinks will be correct
                assert_eq!(shrinks[slot1 as usize], slot1_shrink);
                let slot_vec = (slot1..(slot1 + slots as Slot)).collect::<Vec<_>>();
                let storages = slot_vec
                    .iter()
                    .map(|slot| {
                        let storage = db.storage.get_slot_storage_entry(*slot).unwrap();
                        assert_eq!(*slot, storage.slot());
                        storage
                    })
                    .collect::<Vec<_>>();
                let alive_bytes_expected = storages
                    .iter()
                    .map(|storage| storage.alive_bytes() as u64)
                    .sum::<u64>();
                let infos = match method {
                    TestCollectInfo::CalcAncientSlotInfo => db.calc_ancient_slot_info(
                        slot_vec.clone(),
                        can_randomly_shrink,
                        NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                    ),
                    TestCollectInfo::Add => {
                        continue; // unsupportable
                    }
                    TestCollectInfo::CollectSortFilterInfo => {
                        let tuning = PackedAncientStorageTuning {
                            percent_of_alive_shrunk_data: 100,
                            max_ancient_slots: 0,
                            // irrelevant for what this test is trying to test, but necessary to avoid minimums
                            ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity())
                                .unwrap(),
                            can_randomly_shrink,
                            ..default_tuning()
                        };
                        // note this can sort infos.all_infos
                        db.collect_sort_filter_ancient_slots(slot_vec.clone(), &tuning)
                    }
                };

                assert_eq!(infos.all_infos.len(), 2, "{method:?}");
                storages.iter().for_each(|storage| {
                    assert!(infos
                        .all_infos
                        .iter()
                        .any(|info| info.slot == storage.slot()));
                });
                // data size is so small compared to min aligned file size that the storage is marked as should_shrink
                assert_eq!(
                    infos.shrink_indexes,
                    if matches!(method, TestCollectInfo::CollectSortFilterInfo) {
                        Vec::default()
                    } else {
                        shrinks
                            .iter()
                            .skip(1)
                            .enumerate()
                            .filter_map(|(i, shrink)| shrink.then_some(i))
                            .collect::<Vec<_>>()
                    }
                );
                assert_eq!(infos.total_alive_bytes.0, alive_bytes_expected);
                assert_eq!(infos.total_alive_bytes_shrink.0, dead_bytes);
            }
        }
    }

    fn default_tuning() -> PackedAncientStorageTuning {
        PackedAncientStorageTuning {
            percent_of_alive_shrunk_data: 0,
            max_ancient_slots: 0,
            ideal_storage_size: NonZeroU64::new(1).unwrap(),
            can_randomly_shrink: false,
            max_resulting_storages: NonZeroU64::new(10).unwrap(),
        }
    }

    #[test]
    fn test_clear_should_shrink_after_cutoff_empty() {
        let mut infos = create_test_infos(2);
        for count in 0..2 {
            for i in 0..count {
                infos.all_infos[i].should_shrink = true;
            }
        }
        let tuning = PackedAncientStorageTuning {
            max_ancient_slots: 100,
            ..default_tuning()
        };
        infos.clear_should_shrink_after_cutoff(&tuning);
        assert_eq!(
            0,
            infos
                .all_infos
                .iter()
                .filter_map(|info| info.should_shrink.then_some(()))
                .count()
        );
    }

    #[derive(EnumIter, Debug, PartialEq, Eq)]
    enum TestWriteAncient {
        OnePackedStorage,
        AncientAccounts,
        PackedStorages,
    }

    pub fn build_refs_accounts_from_storage_with_slot(
        accounts: &[(Slot, Vec<AccountFromStorage>)],
    ) -> Vec<(Slot, Vec<&AccountFromStorage>)> {
        accounts
            .iter()
            .map(|(slot, accounts)| (*slot, accounts.iter().collect()))
            .collect::<Vec<_>>()
    }

    pub fn build_refs_accounts_from_storage_with_slot2<'a>(
        accounts: &'a [(Slot, Vec<&'a AccountFromStorage>)],
    ) -> Vec<(Slot, &'a [&'a AccountFromStorage])> {
        accounts
            .iter()
            .map(|(slot, accounts)| (*slot, &accounts[..]))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_write_ancient_accounts() {
        for data_size in [None, Some(10_000_000)] {
            for method in TestWriteAncient::iter() {
                for num_slots in 0..4 {
                    for combine_into in 0..=num_slots {
                        if combine_into == num_slots && num_slots > 0 {
                            // invalid combination when num_slots > 0, but required to hit num_slots=0, combine_into=0
                            continue;
                        }
                        let (db, storages, slots, _infos) =
                            get_sample_storages(num_slots, data_size);

                        let initial_accounts = get_all_accounts(&db, slots.clone());

                        let accounts_byval = storages
                            .iter()
                            .map(|storage| {
                                let mut accounts = Vec::default();
                                storage.accounts.scan_accounts(|account| {
                                    accounts.push(AccountFromStorage::new(&account));
                                });
                                (storage.slot(), accounts)
                            })
                            .collect::<Vec<_>>();

                        // reshape the data
                        let accounts_byval2 =
                            build_refs_accounts_from_storage_with_slot(&accounts_byval);
                        let accounts =
                            build_refs_accounts_from_storage_with_slot2(&accounts_byval2);

                        let target_slot = slots.clone().nth(combine_into).unwrap_or(slots.start);
                        let accounts_to_write =
                            StorableAccountsBySlot::new(target_slot, &accounts, &db);

                        let bytes = storages
                            .iter()
                            .map(|storage| storage.written_bytes())
                            .sum::<u64>();
                        assert_eq!(
                            bytes,
                            initial_accounts
                                .iter()
                                .map(|(_, account)| aligned_stored_size(account.data().len()) as u64)
                                .sum::<u64>()
                        );

                        if num_slots > 0 {
                            let mut write_ancient_accounts = WriteAncientAccounts::default();

                            match method {
                                TestWriteAncient::AncientAccounts => db.write_ancient_accounts(
                                    bytes,
                                    accounts_to_write,
                                    &mut write_ancient_accounts,
                                ),

                                TestWriteAncient::OnePackedStorage => {
                                    let packed = PackedAncientStorage { accounts, bytes };
                                    db.write_one_packed_storage(
                                        &packed,
                                        target_slot,
                                        &mut write_ancient_accounts,
                                    );
                                }
                                TestWriteAncient::PackedStorages => {
                                    let packed = PackedAncientStorage { accounts, bytes };

                                    let accounts_to_combine = AccountsToCombine {
                                        // target slots are supposed to be read in reverse order, so test that
                                        target_slots_sorted: vec![
                                            Slot::MAX, // this asserts if it gets used
                                            Slot::MAX,
                                            target_slot,
                                        ],
                                        ..AccountsToCombine::default()
                                    };

                                    write_ancient_accounts = db
                                        .write_packed_storages(&accounts_to_combine, vec![packed]);
                                }
                            };
                            let mut result = write_ancient_accounts.shrinks_in_progress;
                            let one = result.drain().collect::<Vec<_>>();
                            assert_eq!(1, one.len());
                            assert_eq!(target_slot, one.first().unwrap().0);
                            assert_eq!(
                                one.first().unwrap().1.old_storage().append_vec_id(),
                                storages[combine_into].append_vec_id()
                            );
                            // make sure the single new append vec contains all the same accounts
                            let mut two = Vec::default();
                            one.first()
                                .unwrap()
                                .1
                                .new_storage()
                                .accounts
                                .scan_accounts(|meta| {
                                    two.push((*meta.pubkey(), meta.to_account_shared_data()));
                                });

                            compare_all_accounts(&initial_accounts, &two[..]);
                        }
                        let all_accounts = get_all_accounts(&db, target_slot..(target_slot + 1));

                        compare_all_accounts(&initial_accounts, &all_accounts);
                    }
                }
            }
        }
    }

    #[derive(EnumIter, Debug, PartialEq, Eq)]
    enum TestShouldShrink {
        FilterAncientSlots,
        ClearShouldShrink,
        ChooseStoragesToShrink,
    }

    #[test]
    fn test_clear_should_shrink_after_cutoff_simple() {
        for swap in [false, true] {
            for method in TestShouldShrink::iter() {
                for (percent_of_alive_shrunk_data, mut expected_infos) in
                    [(0, 0), (9, 1), (10, 1), (89, 2), (90, 2), (91, 2), (100, 2)]
                {
                    let mut infos = create_test_infos(2);
                    infos
                        .all_infos
                        .iter_mut()
                        .enumerate()
                        .for_each(|(i, info)| {
                            info.should_shrink = true;
                            info.capacity = ((i + 1) * 1000) as u64;
                        });
                    infos.all_infos[0].alive_bytes = 100;
                    infos.all_infos[1].alive_bytes = 900;
                    if swap {
                        infos.all_infos = infos.all_infos.into_iter().rev().collect();
                    }
                    infos.total_alive_bytes_shrink = Saturating(
                        infos
                            .all_infos
                            .iter()
                            .map(|info| info.alive_bytes)
                            .sum::<u64>(),
                    );
                    let tuning = PackedAncientStorageTuning {
                        percent_of_alive_shrunk_data,
                        // 0 so that we combine everything with regard to the overall # of slots limit
                        max_ancient_slots: 0,
                        // irrelevant for what this test is trying to test, but necessary to avoid minimums
                        ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity())
                            .unwrap(),
                        can_randomly_shrink: false,
                        ..default_tuning()
                    };
                    match method {
                        TestShouldShrink::FilterAncientSlots => {
                            infos.filter_ancient_slots(&tuning, &ShrinkAncientStats::default());
                        }
                        TestShouldShrink::ClearShouldShrink => {
                            infos.clear_should_shrink_after_cutoff(&tuning);
                        }
                        TestShouldShrink::ChooseStoragesToShrink => {
                            infos.choose_storages_to_shrink(&tuning);
                        }
                    }

                    if expected_infos == 2 {
                        let modify = if method == TestShouldShrink::FilterAncientSlots {
                            // filter_ancient_slots modifies in several ways and doesn't retain the values to compare
                            percent_of_alive_shrunk_data == 89 || percent_of_alive_shrunk_data == 90
                        } else {
                            infos.all_infos[infos.shrink_indexes[0]].alive_bytes
                                >= infos.total_alive_bytes_shrink.0 * percent_of_alive_shrunk_data
                                    / 100
                        };
                        if modify {
                            // if the sorting ends up putting the bigger alive_bytes storage first, then only 1 will be shrunk due to 'should_shrink'
                            expected_infos = 1;
                        }
                    }
                    let count = infos
                        .all_infos
                        .iter()
                        .filter_map(|info| info.should_shrink.then_some(()))
                        .count();
                    assert_eq!(
                        expected_infos,
                        count,
                        "percent_of_alive_shrunk_data: {percent_of_alive_shrunk_data}, infos: {expected_infos}, method: {method:?}, swap: {swap}, data: {:?}",
                        infos.all_infos.iter().map(|info| (info.slot, info.capacity, info.alive_bytes)).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn test_sort_shrink_indexes_by_bytes_saved() {
        let (db, slot1) = create_db_with_storages_and_index(true /*alive*/, 1, None);
        let storage = db.storage.get_slot_storage_entry(slot1).unwrap();
        // ignored
        let slot = 0;

        // info1 is first, equal, last
        for info1_capacity in [0, 1, 2] {
            let info1 = SlotInfo {
                storage: storage.clone(),
                slot,
                capacity: info1_capacity,
                alive_bytes: 0,
                should_shrink: false,
                is_high_slot: false,
            };
            let info2 = SlotInfo {
                storage: storage.clone(),
                slot,
                capacity: 2,
                alive_bytes: 1,
                should_shrink: false,
                is_high_slot: false,
            };
            let mut infos = AncientSlotInfos {
                all_infos: vec![info1, info2],
                shrink_indexes: vec![0, 1],
                ..AncientSlotInfos::default()
            };
            infos.sort_shrink_indexes_by_bytes_saved();
            let first = &infos.all_infos[infos.shrink_indexes[0]];
            let second = &infos.all_infos[infos.shrink_indexes[1]];
            let first_capacity = first.capacity - first.alive_bytes;
            let second_capacity = second.capacity - second.alive_bytes;
            assert!(first_capacity >= second_capacity);
        }
    }

    #[test]
    fn test_combine_ancient_slots_packed_internal() {
        let can_randomly_shrink = false;
        let alive = true;
        for num_slots in 0..4 {
            for max_ancient_slots in 0..4 {
                let (db, slot1) = create_db_with_storages_and_index(alive, num_slots, None);
                let original_stores = (0..num_slots)
                    .filter_map(|slot| db.storage.get_slot_storage_entry((slot as Slot) + slot1))
                    .collect::<Vec<_>>();
                let original_results = original_stores
                    .iter()
                    .map(|store| (store.slot(), db.get_unique_accounts_from_storage(store)))
                    .collect::<Vec<_>>();
                let original_results_all_accounts = vec_unique_to_accounts(&original_results, &db);

                let tuning = PackedAncientStorageTuning {
                    percent_of_alive_shrunk_data: 0,
                    max_ancient_slots,
                    can_randomly_shrink,
                    ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
                    ..default_tuning()
                };
                db.combine_ancient_slots_packed_internal(
                    (0..num_slots).map(|slot| (slot as Slot) + slot1).collect(),
                    tuning,
                    &mut ShrinkStatsSub::default(),
                );
                let storage = db.storage.get_slot_storage_entry(slot1);
                if num_slots == 0 {
                    assert!(storage.is_none());
                    continue;
                }
                // any of the several slots could have been chosen to be re-used
                let active_slots = (0..num_slots)
                    .filter_map(|slot| db.storage.get_slot_storage_entry((slot as Slot) + slot1))
                    .count();
                let mut expected_slots = (max_ancient_slots / 2).min(num_slots);
                if max_ancient_slots >= num_slots {
                    expected_slots = num_slots;
                } else if max_ancient_slots == 0 || num_slots > 0 && expected_slots == 0 {
                    expected_slots = 1;
                }
                assert_eq!(
                    active_slots, expected_slots,
                    "slots: {num_slots}, max_ancient_slots: {max_ancient_slots}, alive: {alive}"
                );
                assert_eq!(
                    expected_slots,
                    db.storage.all_slots().len(),
                    "slots: {num_slots}, max_ancient_slots: {max_ancient_slots}"
                );

                let stores = (0..num_slots)
                    .filter_map(|slot| db.storage.get_slot_storage_entry((slot as Slot) + slot1))
                    .collect::<Vec<_>>();
                let results = stores
                    .iter()
                    .map(|store| (store.slot(), db.get_unique_accounts_from_storage(store)))
                    .collect::<Vec<_>>();
                let all_accounts = get_all_accounts(&db, slot1..(slot1 + num_slots as Slot));
                compare_all_accounts(&original_results_all_accounts, &all_accounts);
                compare_all_accounts(
                    &vec_unique_to_accounts(&results, &db),
                    &get_all_accounts(&db, slot1..(slot1 + num_slots as Slot)),
                );
            }
        }
    }

    fn vec_unique_to_accounts(
        one: &[(Slot, GetUniqueAccountsResult)],
        db: &AccountsDb,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        one.iter()
            .flat_map(|(slot, result)| {
                result.stored_accounts.iter().map(|result| {
                    (
                        *result.pubkey(),
                        get_account_from_account_from_storage(result, db, *slot),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn test_combine_packed_ancient_slots_simple() {
        for alive in [false, true] {
            _ = get_one_packed_ancient_append_vec_and_others(alive, 0);
        }
    }

    /// combines ALL possible slots in `sorted_slots`
    fn combine_ancient_slots_packed_for_tests(db: &AccountsDb, sorted_slots: Vec<Slot>) {
        // combine normal append vec(s) into packed ancient append vec
        let tuning = PackedAncientStorageTuning {
            max_ancient_slots: 0,
            // re-combine/shrink 55% of the data savings this pass
            percent_of_alive_shrunk_data: 55,
            ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
            can_randomly_shrink: CAN_RANDOMLY_SHRINK_FALSE,
            ..default_tuning()
        };

        let mut stats_sub = ShrinkStatsSub::default();
        db.combine_ancient_slots_packed_internal(sorted_slots, tuning, &mut stats_sub);
    }

    #[test]
    fn test_shrink_packed_ancient() {
        // NOTE: The recycler has been removed.  Creating this many extra storages is no longer
        // necessary, but also does no harm either.
        const MAX_RECYCLE_STORES: usize = 1000;
        solana_logger::setup();

        // When we pack ancient append vecs, the packed append vecs are recycled first if possible. This means they aren't dropped directly.
        // This test tests that we are releasing Arc refcounts for storages when we pack them into ancient append vecs.
        let db = AccountsDb::new_single_for_tests();
        let initial_slot = 0;
        // create append vecs that we'll fill the recycler with when we pack them into 1 packed append vec
        create_storages_and_update_index(&db, None, initial_slot, MAX_RECYCLE_STORES, true, None);
        let max_slot_inclusive = initial_slot + (MAX_RECYCLE_STORES as Slot) - 1;
        let range = initial_slot..(max_slot_inclusive + 1);
        // storages with Arc::strong_count > 1 cannot be pulled out of the recycling bin, so hold refcounts so these storages are never re-used by the actual test code
        let _storages_hold_to_prevent_recycling = range
            .filter_map(|slot| db.storage.get_slot_storage_entry(slot))
            .collect::<Vec<_>>();

        // fill up the recycler with storages
        combine_ancient_slots_packed_for_tests(&db, (initial_slot..=max_slot_inclusive).collect());

        let mut starting_slot = max_slot_inclusive + 1;
        for num_normal_slots in 1..4 {
            let mut storages = vec![];
            // build an ancient append vec at slot 'ancient_slot'
            let ancient_slot = starting_slot;
            create_storages_and_update_index(&db, None, ancient_slot, num_normal_slots, true, None);
            let max_slot_inclusive = ancient_slot + (num_normal_slots as Slot);
            let range = ancient_slot..(max_slot_inclusive + 1);
            storages.extend(
                range
                    .clone()
                    .filter_map(|slot| db.storage.get_slot_storage_entry(slot)),
            );

            let initial_accounts = get_all_accounts(&db, range);
            compare_all_accounts(
                &initial_accounts,
                &get_all_accounts(&db, ancient_slot..(max_slot_inclusive + 1)),
            );

            combine_ancient_slots_packed_for_tests(
                &db,
                (ancient_slot..=max_slot_inclusive).collect(),
            );

            compare_all_accounts(
                &initial_accounts,
                &get_all_accounts(&db, ancient_slot..(max_slot_inclusive + 1)),
            );
            // verify only `storages` is holding a refcount to each storage we packed
            storages
                .iter()
                .for_each(|storage| assert_eq!(Arc::strong_count(storage), 1));

            // create a 2nd ancient append vec at 'next_slot'
            let next_slot = max_slot_inclusive + 1;
            create_storages_and_update_index(&db, None, next_slot, num_normal_slots, true, None);
            let max_slot_inclusive = next_slot + (num_normal_slots as Slot);
            let range_all = ancient_slot..(max_slot_inclusive + 1);
            let range = next_slot..(max_slot_inclusive + 1);
            storages = vec![];
            storages.extend(
                range
                    .clone()
                    .filter_map(|slot| db.storage.get_slot_storage_entry(slot)),
            );
            let initial_accounts_all = get_all_accounts(&db, range_all.clone());
            let initial_accounts = get_all_accounts(&db, range.clone());
            compare_all_accounts(
                &initial_accounts_all,
                &get_all_accounts(&db, range_all.clone()),
            );
            compare_all_accounts(&initial_accounts, &get_all_accounts(&db, range.clone()));

            combine_ancient_slots_packed_for_tests(&db, range.clone().collect());

            compare_all_accounts(&initial_accounts_all, &get_all_accounts(&db, range_all));
            compare_all_accounts(&initial_accounts, &get_all_accounts(&db, range));

            // verify only `storages` is holding a refcount to each storage we packed
            storages
                .iter()
                .for_each(|storage| assert_eq!(Arc::strong_count(storage), 1));

            starting_slot = max_slot_inclusive + 1;
        }
    }

    #[test]
    fn test_shrink_collect_alive_add() {
        let num_slots = 1;
        let data_size = None;
        let (_db, storages, _slots, _infos) = get_sample_storages(num_slots, data_size);

        storages[0]
            .accounts
            .get_stored_account_meta_callback(0, |stored_account_meta| {
                let account = AccountFromStorage::new(&stored_account_meta);
                let slot = 1;
                let capacity = 0;
                for i in 0..4usize {
                    let mut alive_accounts =
                        ShrinkCollectAliveSeparatedByRefs::with_capacity(capacity, slot);
                    let lamports = 1;

                    match i {
                        0 => {
                            // empty slot list (ignored anyway) because ref_count = 1
                            let slot_list = vec![];
                            alive_accounts.add(1, &account, &slot_list);
                            assert!(!alive_accounts.one_ref.accounts.is_empty());
                            assert!(alive_accounts.many_refs_old_alive.accounts.is_empty());
                            assert!(alive_accounts
                                .many_refs_this_is_newest_alive
                                .accounts
                                .is_empty());
                        }
                        1 => {
                            // non-empty slot list (but ignored) because slot_list = 1
                            let slot_list =
                                vec![(slot, AccountInfo::new(StorageLocation::Cached, lamports))];
                            alive_accounts.add(2, &account, &slot_list);
                            assert!(alive_accounts.one_ref.accounts.is_empty());
                            assert!(alive_accounts.many_refs_old_alive.accounts.is_empty());
                            assert!(!alive_accounts
                                .many_refs_this_is_newest_alive
                                .accounts
                                .is_empty());
                        }
                        2 => {
                            // multiple slot list, ref_count=2, this is NOT newest alive, so many_refs_old_alive
                            let slot_list = vec![
                                (slot, AccountInfo::new(StorageLocation::Cached, lamports)),
                                (
                                    slot + 1,
                                    AccountInfo::new(StorageLocation::Cached, lamports),
                                ),
                            ];
                            alive_accounts.add(2, &account, &slot_list);
                            assert!(alive_accounts.one_ref.accounts.is_empty());
                            assert!(!alive_accounts.many_refs_old_alive.accounts.is_empty());
                            assert!(alive_accounts
                                .many_refs_this_is_newest_alive
                                .accounts
                                .is_empty());
                        }
                        3 => {
                            // multiple slot list, ref_count=2, this is newest
                            let slot_list = vec![
                                (slot, AccountInfo::new(StorageLocation::Cached, lamports)),
                                (
                                    slot - 1,
                                    AccountInfo::new(StorageLocation::Cached, lamports),
                                ),
                            ];
                            alive_accounts.add(2, &account, &slot_list);
                            assert!(alive_accounts.one_ref.accounts.is_empty());
                            assert!(alive_accounts.many_refs_old_alive.accounts.is_empty());
                            assert!(!alive_accounts
                                .many_refs_this_is_newest_alive
                                .accounts
                                .is_empty());
                        }
                        _ => {
                            panic!("unexpected");
                        }
                    }
                }
            });
    }

    #[test]
    fn test_many_ref_accounts_can_be_moved() {
        let tuning = PackedAncientStorageTuning {
            // only allow 10k slots old enough to be ancient
            max_ancient_slots: 10_000,
            // re-combine/shrink 55% of the data savings this pass
            percent_of_alive_shrunk_data: 55,
            ideal_storage_size: NonZeroU64::new(1000).unwrap(),
            can_randomly_shrink: false,
            ..default_tuning()
        };

        // nothing to move, so no problem fitting it
        let many_refs_newest = vec![];
        let target_slots_sorted = vec![];
        assert!(AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));
        // something to move, no target slots, so can't fit
        let slot = 1;
        let many_refs_newest = vec![AliveAccounts {
            bytes: 1,
            slot,
            accounts: Vec::default(),
        }];
        assert!(!AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));

        // something to move, 1 target slot, so can fit
        let target_slots_sorted = vec![slot];
        assert!(AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));

        // too much to move to 1 target slot, so can't fit
        let many_refs_newest = vec![AliveAccounts {
            bytes: tuning.ideal_storage_size.get() as usize,
            slot,
            accounts: Vec::default(),
        }];
        assert!(!AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));

        // more than 1 slot to move, 2 target slots, so can fit
        let target_slots_sorted = vec![slot, slot + 1];
        assert!(AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));

        // lowest target slot is below required slot
        let target_slots_sorted = vec![slot - 1, slot];
        assert!(!AccountsDb::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &target_slots_sorted,
            &tuning
        ));
    }

    #[test]
    fn test_addref_accounts_failed_to_shrink_ancient() {
        let db = AccountsDb::new_single_for_tests();
        let empty_account = AccountSharedData::default();
        for count in 0..3 {
            let unrefed_pubkeys = (0..count)
                .map(|_| solana_sdk::pubkey::new_rand())
                .collect::<Vec<_>>();
            // how many of `many_ref_accounts` should be found in the index with ref_count=1
            let mut expected_ref_counts = HashMap::<Pubkey, u64>::default();

            unrefed_pubkeys.iter().for_each(|k| {
                for slot in 0..2 {
                    // each upsert here (to a different slot) adds a refcount of 1 since entry is NOT cached
                    db.accounts_index.upsert(
                        slot,
                        slot,
                        k,
                        &empty_account,
                        &crate::accounts_index::AccountSecondaryIndexes::default(),
                        AccountInfo::default(),
                        &mut Vec::default(),
                        UpsertReclaim::IgnoreReclaims,
                    );
                }
                // set to 2 initially, made part of `unrefed_pubkeys`, expect it to be addref'd to 3
                expected_ref_counts.insert(*k, 3);
            });

            let shrink_collect = ShrinkCollect::<ShrinkCollectAliveSeparatedByRefs> {
                // the only interesting field
                unrefed_pubkeys: unrefed_pubkeys.iter().collect(),

                // irrelevant fields
                slot: 0,
                capacity: 0,
                alive_accounts: ShrinkCollectAliveSeparatedByRefs {
                    one_ref: AliveAccounts::default(),
                    many_refs_this_is_newest_alive: AliveAccounts::default(),
                    many_refs_old_alive: AliveAccounts::default(),
                },
                alive_total_bytes: 0,
                total_starting_accounts: 0,
                all_are_zero_lamports: false,
                _index_entries_being_shrunk: Vec::default(),
            };
            let accounts_to_combine = AccountsToCombine {
                accounts_keep_slots: HashMap::default(),
                accounts_to_combine: vec![shrink_collect],
                target_slots_sorted: Vec::default(),
                unpackable_slots_count: 0,
            };
            db.addref_accounts_failed_to_shrink_ancient(accounts_to_combine.accounts_to_combine);
            db.accounts_index.scan(
                unrefed_pubkeys.iter(),
                |k, slot_refs, _entry| {
                    assert_eq!(expected_ref_counts.remove(k).unwrap(), slot_refs.unwrap().1);
                    AccountsIndexScanResult::OnlyKeepInMemoryIfDirty
                },
                None,
                false,
            );
            // should have removed all of them
            assert!(expected_ref_counts.is_empty());
        }
    }

    #[test_case(0, 1 => 0)]
    #[test_case(1, 1 => 1)]
    #[test_case(2, 1 => 2)]
    #[test_case(2, 2 => 1)]
    #[test_case(2, 3 => 1)]
    #[test_case(2, 4 => 1)]
    #[test_case(3, 4 => 1)]
    #[test_case(4, 4 => 1)]
    #[test_case(5, 4 => 2)]
    #[test_case(0, u64::MAX => 0)]
    #[test_case(MAXIMUM_APPEND_VEC_FILE_SIZE - 1, MAXIMUM_APPEND_VEC_FILE_SIZE => 1)]
    #[test_case(MAXIMUM_APPEND_VEC_FILE_SIZE + 1, MAXIMUM_APPEND_VEC_FILE_SIZE => 2)]
    fn test_div_ceil(x: u64, y: u64) -> u64 {
        div_ceil(x, NonZeroU64::new(y).unwrap())
    }

    #[should_panic(expected = "x + y must not overflow")]
    #[test_case(1, u64::MAX)]
    #[test_case(u64::MAX, 1)]
    #[test_case(u64::MAX/2 + 2, u64::MAX/2)]
    #[test_case(u64::MAX/2,     u64::MAX/2 + 2)]
    fn test_div_ceil_overflow(x: u64, y: u64) {
        div_ceil(x, NonZeroU64::new(y).unwrap());
    }
}
