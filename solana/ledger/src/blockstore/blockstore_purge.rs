use {
    super::*,
    crate::blockstore_db::ColumnIndexDeprecation,
    solana_sdk::message::AccountKeys,
    std::{cmp::max, time::Instant},
};

#[derive(Default)]
pub struct PurgeStats {
    delete_range: u64,
    write_batch: u64,
    delete_files_in_range: u64,
}

#[derive(Clone, Copy)]
/// Controls how `blockstore::purge_slots` purges the data.
pub enum PurgeType {
    /// A slower but more accurate way to purge slots by also ensuring higher
    /// level of consistency between data during the clean up process.
    Exact,
    /// The fastest purge mode that relies on the slot-id based TTL
    /// compaction filter to do the cleanup.
    CompactionFilter,
}

impl Blockstore {
    /// Performs cleanup based on the specified deletion range.  After this
    /// function call, entries within \[`from_slot`, `to_slot`\] will become
    /// unavailable to the reader immediately, while its disk space occupied
    /// by the deletion entries are reclaimed later via RocksDB's background
    /// compaction.
    ///
    /// Note that this function modifies multiple column families at the same
    /// time and might break the consistency between different column families
    /// as it does not update the associated slot-meta entries that refer to
    /// the deleted entries.
    ///
    /// For slot-id based column families, the purge is done by range deletion,
    /// while the non-slot-id based column families, `cf::TransactionStatus`,
    /// `AddressSignature`, and `cf::TransactionStatusIndex`, are cleaned-up
    /// based on the `purge_type` setting.
    pub fn purge_slots(&self, from_slot: Slot, to_slot: Slot, purge_type: PurgeType) {
        let mut purge_stats = PurgeStats::default();
        let purge_result =
            self.run_purge_with_stats(from_slot, to_slot, purge_type, &mut purge_stats);

        datapoint_info!(
            "blockstore-purge",
            ("from_slot", from_slot as i64, i64),
            ("to_slot", to_slot as i64, i64),
            ("delete_range_us", purge_stats.delete_range as i64, i64),
            ("write_batch_us", purge_stats.write_batch as i64, i64),
            (
                "delete_files_in_range_us",
                purge_stats.delete_files_in_range as i64,
                i64
            )
        );
        if let Err(e) = purge_result {
            error!(
                "Error: {:?}; Purge failed in range {:?} to {:?}",
                e, from_slot, to_slot
            );
        }
    }

    /// Usually this is paired with .purge_slots() but we can't internally call this in
    /// that function unconditionally. That's because set_max_expired_slot()
    /// expects to purge older slots by the successive chronological order, while .purge_slots()
    /// can also be used to purge *future* slots for --hard-fork thing, preserving older
    /// slots. It'd be quite dangerous to purge older slots in that case.
    /// So, current legal user of this function is LedgerCleanupService.
    pub fn set_max_expired_slot(&self, to_slot: Slot) {
        // convert here from inclusive purged range end to inclusive alive range start to align
        // with Slot::default() for initial compaction filter behavior consistency
        let to_slot = to_slot.checked_add(1).unwrap();
        self.db.set_oldest_slot(to_slot);

        if let Err(err) = self.maybe_cleanup_highest_primary_index_slot(to_slot) {
            warn!("Could not clean up TransactionStatusIndex: {err:?}");
        }
    }

    pub fn purge_and_compact_slots(&self, from_slot: Slot, to_slot: Slot) {
        self.purge_slots(from_slot, to_slot, PurgeType::Exact);
    }

    /// Ensures that the SlotMeta::next_slots vector for all slots contain no references in the
    /// \[from_slot,to_slot\] range
    ///
    /// Dangerous; Use with care
    pub fn purge_from_next_slots(&self, from_slot: Slot, to_slot: Slot) {
        let mut count = 0;
        let mut rewritten = 0;
        let mut last_print = Instant::now();
        let mut total_retain_us = 0;
        for (slot, mut meta) in self
            .slot_meta_iterator(0)
            .expect("unable to iterate over meta")
        {
            if slot > to_slot {
                break;
            }

            count += 1;
            if last_print.elapsed().as_millis() > 2000 {
                info!(
                    "purged: {} slots rewritten: {} retain_time: {}us",
                    count, rewritten, total_retain_us
                );
                count = 0;
                rewritten = 0;
                total_retain_us = 0;
                last_print = Instant::now();
            }
            let mut time = Measure::start("retain");
            let original_len = meta.next_slots.len();
            meta.next_slots
                .retain(|slot| *slot < from_slot || *slot > to_slot);
            if meta.next_slots.len() != original_len {
                rewritten += 1;
                info!(
                    "purge_from_next_slots: meta for slot {} no longer refers to slots {:?}",
                    slot,
                    from_slot..=to_slot
                );
                self.put_meta_bytes(
                    slot,
                    &bincode::serialize(&meta).expect("couldn't update meta"),
                )
                .expect("couldn't update meta");
            }
            time.stop();
            total_retain_us += time.as_us();
        }
    }

    #[cfg(test)]
    pub(crate) fn run_purge(
        &self,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
    ) -> Result<bool> {
        self.run_purge_with_stats(from_slot, to_slot, purge_type, &mut PurgeStats::default())
    }

    /// Purges all columns relating to `slot`.
    ///
    /// Additionally, we cleanup the parent of `slot` by clearing `slot` from
    /// the parent's `next_slots`. We reinsert an orphaned `slot_meta` for `slot`
    /// that preserves `slot`'s `next_slots`. This ensures that `slot`'s fork is
    /// replayable upon repair of `slot`.
    pub(crate) fn purge_slot_cleanup_chaining(&self, slot: Slot) -> Result<bool> {
        let Some(mut slot_meta) = self.meta(slot)? else {
            return Err(BlockstoreError::SlotUnavailable);
        };
        let mut write_batch = self.db.batch()?;

        let columns_purged = self.purge_range(&mut write_batch, slot, slot, PurgeType::Exact)?;

        if let Some(parent_slot) = slot_meta.parent_slot {
            let parent_slot_meta = self.meta(parent_slot)?;
            if let Some(mut parent_slot_meta) = parent_slot_meta {
                // .retain() is a linear scan; however, next_slots should
                // only contain several elements so this isn't so bad
                parent_slot_meta
                    .next_slots
                    .retain(|&next_slot| next_slot != slot);
                write_batch.put::<cf::SlotMeta>(parent_slot, &parent_slot_meta)?;
            } else {
                error!(
                    "Parent slot meta {} for child {} is missing  or cleaned up.
                       Falling back to orphan repair to remedy the situation",
                    parent_slot, slot
                );
            }
        }

        // Retain a SlotMeta for `slot` with the `next_slots` field retained
        slot_meta.clear_unconfirmed_slot();
        write_batch.put::<cf::SlotMeta>(slot, &slot_meta)?;

        self.db.write(write_batch).inspect_err(|e| {
            error!(
                "Error: {:?} while submitting write batch for slot {:?}",
                e, slot
            )
        })?;
        Ok(columns_purged)
    }

    /// A helper function to `purge_slots` that executes the ledger clean up.
    /// The cleanup applies to \[`from_slot`, `to_slot`\].
    ///
    /// When `from_slot` is 0, any sst-file with a key-range completely older
    /// than `to_slot` will also be deleted.
    ///
    /// Note: slots > `to_slot` that chained to a purged slot are not properly
    /// cleaned up. This function is not intended to be used if such slots need
    /// to be replayed.
    pub(crate) fn run_purge_with_stats(
        &self,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
        purge_stats: &mut PurgeStats,
    ) -> Result<bool> {
        let mut write_batch = self.db.batch()?;

        let mut delete_range_timer = Measure::start("delete_range");
        let columns_purged = self.purge_range(&mut write_batch, from_slot, to_slot, purge_type)?;
        delete_range_timer.stop();

        let mut write_timer = Measure::start("write_batch");
        self.db.write(write_batch).inspect_err(|e| {
            error!(
                "Error: {:?} while submitting write batch for purge from_slot {} to_slot {}",
                e, from_slot, to_slot
            )
        })?;
        write_timer.stop();

        let mut purge_files_in_range_timer = Measure::start("delete_file_in_range");
        // purge_files_in_range delete any files whose slot range is within
        // [from_slot, to_slot].  When from_slot is 0, it is safe to run
        // purge_files_in_range because if purge_files_in_range deletes any
        // sst file that contains any range-deletion tombstone, the deletion
        // range of that tombstone will be completely covered by the new
        // range-delete tombstone (0, to_slot) issued above.
        //
        // On the other hand, purge_files_in_range is more effective and
        // efficient than the compaction filter (which runs key-by-key)
        // because all the sst files that have key range below to_slot
        // can be deleted immediately.
        if columns_purged && from_slot == 0 {
            self.purge_files_in_range(from_slot, to_slot);
        }
        purge_files_in_range_timer.stop();

        purge_stats.delete_range += delete_range_timer.as_us();
        purge_stats.write_batch += write_timer.as_us();
        purge_stats.delete_files_in_range += purge_files_in_range_timer.as_us();

        Ok(columns_purged)
    }

    fn purge_range(
        &self,
        write_batch: &mut WriteBatch,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
    ) -> Result<bool> {
        let columns_purged = self
            .db
            .delete_range_cf::<cf::SlotMeta>(write_batch, from_slot, to_slot)
            .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BankHash>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Root>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredData>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredCode>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DeadSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DuplicateSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ErasureMeta>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Orphans>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Index>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Rewards>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Blocktime>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::PerfSamples>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BlockHeight>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::OptimisticSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::MerkleRootMeta>(write_batch, from_slot, to_slot)
                .is_ok();

        match purge_type {
            PurgeType::Exact => {
                self.purge_special_columns_exact(write_batch, from_slot, to_slot)?;
            }
            PurgeType::CompactionFilter => {
                // No explicit action is required here because this purge type completely and
                // indefinitely relies on the proper working of compaction filter for those
                // special column families, never toggling the primary index from the current
                // one. Overall, this enables well uniformly distributed writes, resulting
                // in no spiky periodic huge delete_range for them.
            }
        }
        Ok(columns_purged)
    }

    fn purge_files_in_range(&self, from_slot: Slot, to_slot: Slot) -> bool {
        self.db
            .delete_file_in_range_cf::<cf::SlotMeta>(from_slot, to_slot)
            .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::BankHash>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Root>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ShredData>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ShredCode>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::DeadSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::DuplicateSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ErasureMeta>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Orphans>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Index>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Rewards>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Blocktime>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::PerfSamples>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::BlockHeight>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::OptimisticSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::MerkleRootMeta>(from_slot, to_slot)
                .is_ok()
    }

    /// Returns true if the special columns, TransactionStatus and
    /// AddressSignatures, are both empty.
    ///
    /// It should not be the case that one is empty and the other is not, but
    /// just return false in this case.
    fn special_columns_empty(&self) -> Result<bool> {
        let transaction_status_empty = self
            .transaction_status_cf
            .iter(IteratorMode::Start)?
            .next()
            .is_none();
        let address_signatures_empty = self
            .address_signatures_cf
            .iter(IteratorMode::Start)?
            .next()
            .is_none();

        Ok(transaction_status_empty && address_signatures_empty)
    }

    /// Purges special columns (using a non-Slot primary-index) exactly, by
    /// deserializing each slot being purged and iterating through all
    /// transactions to determine the keys of individual records.
    ///
    /// The purge range applies to \[`from_slot`, `to_slot`\].
    ///
    /// **This method is very slow.**
    fn purge_special_columns_exact(
        &self,
        batch: &mut WriteBatch,
        from_slot: Slot,
        to_slot: Slot,
    ) -> Result<()> {
        if self.special_columns_empty()? {
            return Ok(());
        }

        let mut index0 = self.transaction_status_index_cf.get(0)?.unwrap_or_default();
        let mut index1 = self.transaction_status_index_cf.get(1)?.unwrap_or_default();
        let highest_primary_index_slot = self.get_highest_primary_index_slot();
        let slot_indexes = |slot: Slot| -> Vec<u64> {
            let mut indexes = vec![];
            if highest_primary_index_slot.is_none() {
                return indexes;
            }
            if slot <= index0.max_slot && (index0.frozen || slot >= index1.max_slot) {
                indexes.push(0);
            }
            if slot <= index1.max_slot && (index1.frozen || slot >= index0.max_slot) {
                indexes.push(1);
            }
            indexes
        };

        for slot in from_slot..=to_slot {
            let primary_indexes = slot_indexes(slot);

            let (slot_entries, _, _) =
                self.get_slot_entries_with_shred_info(slot, 0, true /* allow_dead_slots */)?;
            let transactions = slot_entries
                .into_iter()
                .flat_map(|entry| entry.transactions);
            for (i, transaction) in transactions.enumerate() {
                if let Some(&signature) = transaction.signatures.first() {
                    batch.delete::<cf::TransactionStatus>((signature, slot))?;
                    batch.delete::<cf::TransactionMemos>((signature, slot))?;
                    if !primary_indexes.is_empty() {
                        batch.delete_raw::<cf::TransactionMemos>(
                            &cf::TransactionMemos::deprecated_key(signature),
                        )?;
                    }
                    for primary_index in &primary_indexes {
                        batch.delete_raw::<cf::TransactionStatus>(
                            &cf::TransactionStatus::deprecated_key((
                                *primary_index,
                                signature,
                                slot,
                            )),
                        )?;
                    }

                    let meta = self.read_transaction_status((signature, slot))?;
                    let loaded_addresses = meta.map(|meta| meta.loaded_addresses);
                    let account_keys = AccountKeys::new(
                        transaction.message.static_account_keys(),
                        loaded_addresses.as_ref(),
                    );

                    let transaction_index =
                        u32::try_from(i).map_err(|_| BlockstoreError::TransactionIndexOverflow)?;
                    for pubkey in account_keys.iter() {
                        batch.delete::<cf::AddressSignatures>((
                            *pubkey,
                            slot,
                            transaction_index,
                            signature,
                        ))?;
                        for primary_index in &primary_indexes {
                            batch.delete_raw::<cf::AddressSignatures>(
                                &cf::AddressSignatures::deprecated_key((
                                    *primary_index,
                                    *pubkey,
                                    slot,
                                    signature,
                                )),
                            )?;
                        }
                    }
                }
            }
        }
        let mut update_highest_primary_index_slot = false;
        if index0.max_slot >= from_slot && index0.max_slot <= to_slot {
            index0.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(0, &index0)?;
            update_highest_primary_index_slot = true;
        }
        if index1.max_slot >= from_slot && index1.max_slot <= to_slot {
            index1.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(1, &index1)?;
            update_highest_primary_index_slot = true
        }
        if update_highest_primary_index_slot {
            self.set_highest_primary_index_slot(Some(max(index0.max_slot, index1.max_slot)))
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use {
        super::*,
        crate::{
            blockstore::tests::make_slot_entries_with_transactions, get_tmp_ledger_path_auto_delete,
        },
        bincode::serialize,
        solana_entry::entry::next_entry_mut,
        solana_sdk::{
            hash::{hash, Hash},
            message::Message,
            transaction::Transaction,
        },
        test_case::test_case,
    };

    #[test]
    fn test_purge_slots() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let (shreds, _) = make_many_slot_entries(0, 50, 5);
        blockstore.insert_shreds(shreds, None, false).unwrap();

        blockstore.purge_and_compact_slots(0, 5);

        test_all_empty_or_min(&blockstore, 6);

        blockstore.purge_and_compact_slots(0, 50);

        // min slot shouldn't matter, blockstore should be empty
        test_all_empty_or_min(&blockstore, 100);
        test_all_empty_or_min(&blockstore, 0);

        blockstore
            .slot_meta_iterator(0)
            .unwrap()
            .for_each(|(_, _)| {
                panic!();
            });
    }

    #[test]
    fn test_purge_front_of_ledger() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let max_slot = 10;
        for x in 0..max_slot {
            let random_bytes: [u8; 64] = std::array::from_fn(|_| rand::random::<u8>());
            blockstore
                .write_transaction_status(
                    x,
                    Signature::from(random_bytes),
                    vec![&Pubkey::try_from(&random_bytes[..32]).unwrap()],
                    vec![&Pubkey::try_from(&random_bytes[32..]).unwrap()],
                    TransactionStatusMeta::default(),
                    0,
                )
                .unwrap();
        }

        // Purging range outside of TransactionStatus max slots should not affect TransactionStatus data
        blockstore.run_purge(10, 20, PurgeType::Exact).unwrap();

        let status_entries: Vec<_> = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap()
            .collect();
        assert_eq!(status_entries.len(), 10);
    }

    fn clear_and_repopulate_transaction_statuses_for_test(blockstore: &Blockstore, max_slot: u64) {
        blockstore.run_purge(0, max_slot, PurgeType::Exact).unwrap();
        let mut iter = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        assert_eq!(iter.next(), None);

        populate_transaction_statuses_for_test(blockstore, 0, max_slot);
    }

    fn populate_transaction_statuses_for_test(
        blockstore: &Blockstore,
        min_slot: u64,
        max_slot: u64,
    ) {
        for x in min_slot..=max_slot {
            let entries = make_slot_entries_with_transactions(1);
            let shreds = entries_to_test_shreds(
                &entries,
                x,                   // slot
                x.saturating_sub(1), // parent_slot
                true,                // is_full_slot
                0,                   // version
                true,                // merkle_variant
            );
            blockstore.insert_shreds(shreds, None, false).unwrap();
            let signature = entries
                .iter()
                .filter(|entry| !entry.is_tick())
                .cloned()
                .flat_map(|entry| entry.transactions)
                .map(|transaction| transaction.signatures[0])
                .collect::<Vec<Signature>>()[0];
            let random_bytes: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
            blockstore
                .write_transaction_status(
                    x,
                    signature,
                    vec![&Pubkey::try_from(&random_bytes[..32]).unwrap()],
                    vec![&Pubkey::try_from(&random_bytes[32..]).unwrap()],
                    TransactionStatusMeta::default(),
                    0,
                )
                .unwrap();
        }
    }

    fn populate_deprecated_transaction_statuses_for_test(
        blockstore: &Blockstore,
        primary_index: u64,
        min_slot: u64,
        max_slot: u64,
    ) {
        for x in min_slot..=max_slot {
            let entries = make_slot_entries_with_transactions(1);
            let shreds = entries_to_test_shreds(
                &entries,
                x,                   // slot
                x.saturating_sub(1), // parent_slot
                true,                // is_full_slot
                0,                   // version
                true,                // merkle_variant
            );
            blockstore.insert_shreds(shreds, None, false).unwrap();
            let signature = entries
                .iter()
                .filter(|entry| !entry.is_tick())
                .cloned()
                .flat_map(|entry| entry.transactions)
                .map(|transaction| transaction.signatures[0])
                .collect::<Vec<Signature>>()[0];
            let random_bytes: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
            blockstore
                .write_deprecated_transaction_status(
                    primary_index,
                    x,
                    signature,
                    vec![&Pubkey::try_from(&random_bytes[..32]).unwrap()],
                    vec![&Pubkey::try_from(&random_bytes[32..]).unwrap()],
                    TransactionStatusMeta::default(),
                )
                .unwrap();
        }
    }

    #[test]
    fn test_special_columns_empty() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        // Nothing has been inserted yet
        assert!(blockstore.special_columns_empty().unwrap());

        let num_entries = 1;
        let max_slot = 9;
        for slot in 0..=max_slot {
            let entries = make_slot_entries_with_transactions(num_entries);
            let shreds = entries_to_test_shreds(
                &entries,
                slot,
                slot.saturating_sub(1),
                true, // is_full_slot
                0,    // version
                true, // merkle_variant
            );
            blockstore.insert_shreds(shreds, None, false).unwrap();

            for transaction in entries.into_iter().flat_map(|entry| entry.transactions) {
                assert_eq!(transaction.signatures.len(), 1);
                blockstore
                    .write_transaction_status(
                        slot,
                        transaction.signatures[0],
                        transaction.message.static_account_keys().iter().collect(),
                        vec![],
                        TransactionStatusMeta::default(),
                        0,
                    )
                    .unwrap();
            }
        }
        assert!(!blockstore.special_columns_empty().unwrap());

        // Partially purge and ensure special columns are non-empty
        blockstore
            .run_purge(0, max_slot - 5, PurgeType::Exact)
            .unwrap();
        assert!(!blockstore.special_columns_empty().unwrap());

        // Purge the rest and ensure the special columns are empty once again
        blockstore.run_purge(0, max_slot, PurgeType::Exact).unwrap();
        assert!(blockstore.special_columns_empty().unwrap());
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_purge_transaction_status_exact() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let max_slot = 9;

        // Test purge outside bounds
        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        blockstore.run_purge(10, 12, PurgeType::Exact).unwrap();

        let mut status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        for _ in 0..max_slot + 1 {
            let entry = status_entry_iterator.next().unwrap().0;
            assert!(entry.1 <= max_slot || entry.1 > 0);
        }
        assert_eq!(status_entry_iterator.next(), None);
        drop(status_entry_iterator);

        // Test purge inside written range
        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        blockstore.run_purge(2, 4, PurgeType::Exact).unwrap();

        let mut status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        for _ in 0..7 {
            // 7 entries remaining
            let entry = status_entry_iterator.next().unwrap().0;
            assert!(entry.1 < 2 || entry.1 > 4);
        }
        assert_eq!(status_entry_iterator.next(), None);
        drop(status_entry_iterator);

        // Purge up to but not including max_slot
        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        blockstore
            .run_purge(0, max_slot - 1, PurgeType::Exact)
            .unwrap();

        let mut status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        let entry = status_entry_iterator.next().unwrap().0;
        assert_eq!(entry.1, 9);
        assert_eq!(status_entry_iterator.next(), None);
        drop(status_entry_iterator);

        // Test purge all
        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        blockstore.run_purge(0, 22, PurgeType::Exact).unwrap();

        let mut status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        assert_eq!(status_entry_iterator.next(), None);
    }

    fn get_index_bounds(blockstore: &Blockstore) -> (Box<[u8]>, Box<[u8]>) {
        let first_index = {
            let mut status_entry_iterator = blockstore
                .transaction_status_cf
                .iterator_cf_raw_key(IteratorMode::Start);
            status_entry_iterator.next().unwrap().unwrap().0
        };
        let last_index = {
            let mut status_entry_iterator = blockstore
                .transaction_status_cf
                .iterator_cf_raw_key(IteratorMode::End);
            status_entry_iterator.next().unwrap().unwrap().0
        };
        (first_index, last_index)
    }

    fn purge_exact(blockstore: &Blockstore, oldest_slot: Slot) {
        blockstore
            .run_purge(0, oldest_slot - 1, PurgeType::Exact)
            .unwrap();
    }

    fn purge_compaction_filter(blockstore: &Blockstore, oldest_slot: Slot) {
        let (first_index, last_index) = get_index_bounds(blockstore);
        blockstore.db.set_oldest_slot(oldest_slot);
        blockstore
            .db
            .compact_range_cf::<cf::TransactionStatus>(&first_index, &last_index);
    }

    #[test_case(purge_exact; "exact")]
    #[test_case(purge_compaction_filter; "compaction_filter")]
    fn test_purge_special_columns_with_old_data(purge: impl Fn(&Blockstore, Slot)) {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        populate_deprecated_transaction_statuses_for_test(&blockstore, 0, 0, 4);
        populate_deprecated_transaction_statuses_for_test(&blockstore, 1, 5, 9);
        populate_transaction_statuses_for_test(&blockstore, 10, 14);

        let mut index0 = blockstore
            .transaction_status_index_cf
            .get(0)
            .unwrap()
            .unwrap_or_default();
        index0.frozen = true;
        index0.max_slot = 4;
        blockstore
            .transaction_status_index_cf
            .put(0, &index0)
            .unwrap();
        let mut index1 = blockstore
            .transaction_status_index_cf
            .get(1)
            .unwrap()
            .unwrap_or_default();
        index1.frozen = false;
        index1.max_slot = 9;
        blockstore
            .transaction_status_index_cf
            .put(1, &index1)
            .unwrap();

        let statuses: Vec<_> = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start)
            .collect();
        assert_eq!(statuses.len(), 15);

        // Delete some of primary-index 0
        let oldest_slot = 3;
        purge(&blockstore, oldest_slot);
        let status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for entry in status_entry_iterator {
            let (key, _value) = entry.unwrap();
            let (_signature, slot) = <cf::TransactionStatus as Column>::index(&key);
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 12);

        // Delete the rest of primary-index 0
        let oldest_slot = 5;
        purge(&blockstore, oldest_slot);
        let status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for entry in status_entry_iterator {
            let (key, _value) = entry.unwrap();
            let (_signature, slot) = <cf::TransactionStatus as Column>::index(&key);
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 10);

        // Delete some of primary-index 1
        let oldest_slot = 8;
        purge(&blockstore, oldest_slot);
        let status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for entry in status_entry_iterator {
            let (key, _value) = entry.unwrap();
            let (_signature, slot) = <cf::TransactionStatus as Column>::index(&key);
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 7);

        // Delete the rest of primary-index 1
        let oldest_slot = 10;
        purge(&blockstore, oldest_slot);
        let status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for entry in status_entry_iterator {
            let (key, _value) = entry.unwrap();
            let (_signature, slot) = <cf::TransactionStatus as Column>::index(&key);
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 5);

        // Delete some of new-style entries
        let oldest_slot = 13;
        purge(&blockstore, oldest_slot);
        let status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for entry in status_entry_iterator {
            let (key, _value) = entry.unwrap();
            let (_signature, slot) = <cf::TransactionStatus as Column>::index(&key);
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 2);

        // Delete the rest of the new-style entries
        let oldest_slot = 20;
        purge(&blockstore, oldest_slot);
        let mut status_entry_iterator = blockstore
            .transaction_status_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        assert!(status_entry_iterator.next().is_none());
    }

    #[test]
    fn test_purge_special_columns_exact_no_sigs() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let slot = 1;
        let mut entries: Vec<Entry> = vec![];
        for x in 0..5 {
            let mut tx = Transaction::new_unsigned(Message::default());
            tx.signatures = vec![];
            entries.push(next_entry_mut(&mut Hash::default(), 0, vec![tx]));
            let mut tick = create_ticks(1, 0, hash(&serialize(&x).unwrap()));
            entries.append(&mut tick);
        }
        let shreds = entries_to_test_shreds(
            &entries,
            slot,
            slot - 1, // parent_slot
            true,     // is_full_slot
            0,        // version
            true,     // merkle_variant
        );
        blockstore.insert_shreds(shreds, None, false).unwrap();

        let mut write_batch = blockstore.db.batch().unwrap();
        blockstore
            .purge_special_columns_exact(&mut write_batch, slot, slot + 1)
            .unwrap();
    }

    #[test]
    fn test_purge_special_columns_compaction_filter() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let max_slot = 19;

        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        let first_index = {
            let mut status_entry_iterator = blockstore
                .db
                .iter::<cf::TransactionStatus>(IteratorMode::Start)
                .unwrap();
            status_entry_iterator.next().unwrap().0
        };
        let last_index = {
            let mut status_entry_iterator = blockstore
                .db
                .iter::<cf::TransactionStatus>(IteratorMode::End)
                .unwrap();
            status_entry_iterator.next().unwrap().0
        };

        let oldest_slot = 3;
        blockstore.db.set_oldest_slot(oldest_slot);
        blockstore.db.compact_range_cf::<cf::TransactionStatus>(
            &cf::TransactionStatus::key(first_index),
            &cf::TransactionStatus::key(last_index),
        );

        let status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        let mut count = 0;
        for ((_signature, slot), _value) in status_entry_iterator {
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, max_slot - (oldest_slot - 1));

        clear_and_repopulate_transaction_statuses_for_test(&blockstore, max_slot);
        let first_index = {
            let mut status_entry_iterator = blockstore
                .db
                .iter::<cf::TransactionStatus>(IteratorMode::Start)
                .unwrap();
            status_entry_iterator.next().unwrap().0
        };
        let last_index = {
            let mut status_entry_iterator = blockstore
                .db
                .iter::<cf::TransactionStatus>(IteratorMode::End)
                .unwrap();
            status_entry_iterator.next().unwrap().0
        };

        let oldest_slot = 12;
        blockstore.db.set_oldest_slot(oldest_slot);
        blockstore.db.compact_range_cf::<cf::TransactionStatus>(
            &cf::TransactionStatus::key(first_index),
            &cf::TransactionStatus::key(last_index),
        );

        let status_entry_iterator = blockstore
            .db
            .iter::<cf::TransactionStatus>(IteratorMode::Start)
            .unwrap();
        let mut count = 0;
        for ((_signature, slot), _value) in status_entry_iterator {
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, max_slot - (oldest_slot - 1));
    }

    #[test]
    fn test_purge_transaction_memos_compaction_filter() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();
        let oldest_slot = 5;

        fn random_signature() -> Signature {
            use rand::Rng;

            let mut key = [0u8; 64];
            rand::thread_rng().fill(&mut key[..]);
            Signature::from(key)
        }

        // Insert some deprecated TransactionMemos
        blockstore
            .transaction_memos_cf
            .put_deprecated(random_signature(), &"this is a memo".to_string())
            .unwrap();
        blockstore
            .transaction_memos_cf
            .put_deprecated(random_signature(), &"another memo".to_string())
            .unwrap();
        // Set clean_slot_0 to false, since we have deprecated memos
        blockstore.db.set_clean_slot_0(false);

        // Insert some current TransactionMemos
        blockstore
            .transaction_memos_cf
            .put(
                (random_signature(), oldest_slot - 1),
                &"this is a new memo in slot 4".to_string(),
            )
            .unwrap();
        blockstore
            .transaction_memos_cf
            .put(
                (random_signature(), oldest_slot),
                &"this is a memo in slot 5 ".to_string(),
            )
            .unwrap();

        let first_index = {
            let mut memos_iterator = blockstore
                .transaction_memos_cf
                .iterator_cf_raw_key(IteratorMode::Start);
            memos_iterator.next().unwrap().unwrap().0
        };
        let last_index = {
            let mut memos_iterator = blockstore
                .transaction_memos_cf
                .iterator_cf_raw_key(IteratorMode::End);
            memos_iterator.next().unwrap().unwrap().0
        };

        // Purge at slot 0 should not affect any memos
        blockstore.db.set_oldest_slot(0);
        blockstore
            .db
            .compact_range_cf::<cf::TransactionMemos>(&first_index, &last_index);
        let memos_iterator = blockstore
            .transaction_memos_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for item in memos_iterator {
            let _item = item.unwrap();
            count += 1;
        }
        assert_eq!(count, 4);

        // Purge at oldest_slot without clean_slot_0 only purges the current memo at slot 4
        blockstore.db.set_oldest_slot(oldest_slot);
        blockstore
            .db
            .compact_range_cf::<cf::TransactionMemos>(&first_index, &last_index);
        let memos_iterator = blockstore
            .transaction_memos_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for item in memos_iterator {
            let (key, _value) = item.unwrap();
            let slot = <cf::TransactionMemos as Column>::index(&key).1;
            assert!(slot == 0 || slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 3);

        // Purge at oldest_slot with clean_slot_0 purges deprecated memos
        blockstore.db.set_clean_slot_0(true);
        blockstore
            .db
            .compact_range_cf::<cf::TransactionMemos>(&first_index, &last_index);
        let memos_iterator = blockstore
            .transaction_memos_cf
            .iterator_cf_raw_key(IteratorMode::Start);
        let mut count = 0;
        for item in memos_iterator {
            let (key, _value) = item.unwrap();
            let slot = <cf::TransactionMemos as Column>::index(&key).1;
            assert!(slot >= oldest_slot);
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_purge_slot_cleanup_chaining_missing_slot_meta() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let (shreds, _) = make_many_slot_entries(0, 10, 5);
        blockstore.insert_shreds(shreds, None, false).unwrap();

        assert!(matches!(
            blockstore.purge_slot_cleanup_chaining(11).unwrap_err(),
            BlockstoreError::SlotUnavailable
        ));
    }

    #[test]
    fn test_purge_slot_cleanup_chaining() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path()).unwrap();

        let (shreds, _) = make_many_slot_entries(0, 10, 5);
        blockstore.insert_shreds(shreds, None, false).unwrap();
        let (slot_11, _) = make_slot_entries(11, 4, 5, true);
        blockstore.insert_shreds(slot_11, None, false).unwrap();
        let (slot_12, _) = make_slot_entries(12, 5, 5, true);
        blockstore.insert_shreds(slot_12, None, false).unwrap();

        blockstore.purge_slot_cleanup_chaining(5).unwrap();

        let slot_meta = blockstore.meta(5).unwrap().unwrap();
        let expected_slot_meta = SlotMeta {
            slot: 5,
            // Only the next_slots should be preserved
            next_slots: vec![6, 12],
            ..SlotMeta::default()
        };
        assert_eq!(slot_meta, expected_slot_meta);

        let parent_slot_meta = blockstore.meta(4).unwrap().unwrap();
        assert_eq!(parent_slot_meta.next_slots, vec![11]);

        let child_slot_meta = blockstore.meta(6).unwrap().unwrap();
        assert_eq!(child_slot_meta.parent_slot.unwrap(), 5);

        let child_slot_meta = blockstore.meta(12).unwrap().unwrap();
        assert_eq!(child_slot_meta.parent_slot.unwrap(), 5);
    }
}
