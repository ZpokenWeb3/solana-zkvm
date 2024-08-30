use {
    crate::{account_storage::meta::StoredAccountMeta, accounts_db::AccountsDb},
    solana_measure::measure::Measure,
    solana_metrics::*,
    solana_sdk::{
        account::AccountSharedData, clock::Slot, pubkey::Pubkey, transaction::SanitizedTransaction,
    },
    std::collections::{HashMap, HashSet},
};

#[derive(Default)]
pub struct GeyserPluginNotifyAtSnapshotRestoreStats {
    pub total_accounts: usize,
    pub skipped_accounts: usize,
    pub notified_accounts: usize,
    pub elapsed_filtering_us: usize,
    pub total_pure_notify: usize,
    pub total_pure_bookeeping: usize,
    pub elapsed_notifying_us: usize,
}

impl GeyserPluginNotifyAtSnapshotRestoreStats {
    pub fn report(&self) {
        datapoint_info!(
            "accountsdb_plugin_notify_account_restore_from_snapshot_summary",
            ("total_accounts", self.total_accounts, i64),
            ("skipped_accounts", self.skipped_accounts, i64),
            ("notified_accounts", self.notified_accounts, i64),
            ("elapsed_filtering_us", self.elapsed_filtering_us, i64),
            ("elapsed_notifying_us", self.elapsed_notifying_us, i64),
            ("total_pure_notify_us", self.total_pure_notify, i64),
            ("total_pure_bookeeping_us", self.total_pure_bookeeping, i64),
        );
    }
}

impl AccountsDb {
    /// Notify the plugins of of account data when AccountsDb is restored from a snapshot. The data is streamed
    /// in the reverse order of the slots so that an account is only streamed once. At a slot, if the accounts is updated
    /// multiple times only the last write (with highest write_version) is notified.
    pub fn notify_account_restore_from_snapshot(&self) {
        if self.accounts_update_notifier.is_none() {
            return;
        }

        let mut slots = self.storage.all_slots();
        let mut notified_accounts: HashSet<Pubkey> = HashSet::default();
        let mut notify_stats = GeyserPluginNotifyAtSnapshotRestoreStats::default();

        slots.sort_by(|a, b| b.cmp(a));
        for slot in slots {
            self.notify_accounts_in_slot(slot, &mut notified_accounts, &mut notify_stats);
        }

        let accounts_update_notifier = self.accounts_update_notifier.as_ref().unwrap();
        accounts_update_notifier.notify_end_of_restore_from_snapshot();
        notify_stats.report();
    }

    pub fn notify_account_at_accounts_update<P>(
        &self,
        slot: Slot,
        account: &AccountSharedData,
        txn: &Option<&SanitizedTransaction>,
        pubkey: &Pubkey,
        write_version_producer: &mut P,
    ) where
        P: Iterator<Item = u64>,
    {
        if let Some(accounts_update_notifier) = &self.accounts_update_notifier {
            accounts_update_notifier.notify_account_update(
                slot,
                account,
                txn,
                pubkey,
                write_version_producer.next().unwrap(),
            );
        }
    }

    fn notify_accounts_in_slot(
        &self,
        slot: Slot,
        notified_accounts: &mut HashSet<Pubkey>,
        notify_stats: &mut GeyserPluginNotifyAtSnapshotRestoreStats,
    ) {
        let storage_entry = self.storage.get_slot_storage_entry(slot).unwrap();

        let mut accounts_duplicate: HashMap<Pubkey, usize> = HashMap::default();
        let mut measure_filter = Measure::start("accountsdb-plugin-filtering-accounts");
        let mut account_len = 0;
        let mut pubkeys = HashSet::new();

        // populate `accounts_duplicate` for any pubkeys that are in this storage twice.
        // Storages cannot return `StoredAccountMeta<'_>` for more than 1 account at a time, so we have to do 2 passes to make sure
        // we don't have duplicate pubkeys.
        let mut i = 0;
        storage_entry.accounts.scan_pubkeys(|pubkey| {
            i += 1; // pre-increment to most easily match early returns in next loop
            if !pubkeys.insert(*pubkey) {
                accounts_duplicate.insert(*pubkey, i); // remember the highest index entry in this slot
            }
        });

        // now, actually notify geyser
        let mut i = 0;
        storage_entry.accounts.scan_accounts(|account| {
            i += 1;
            account_len += 1;
            if notified_accounts.contains(account.pubkey()) {
                notify_stats.skipped_accounts += 1;
                return;
            }
            if let Some(highest_i) = accounts_duplicate.get(account.pubkey()) {
                if highest_i != &i {
                    // this pubkey is in this storage twice and the current instance is not the last one, so we skip it.
                    // We only send unique accounts in this slot to `notify_filtered_accounts`
                    return;
                }
            }

            // later entries in the same slot are more recent and override earlier accounts for the same pubkey
            // We can pass an incrementing number here for write_version in the future, if the storage does not have a write_version.
            // As long as all accounts for this slot are in 1 append vec that can be iterated oldest to newest.
            self.notify_filtered_accounts(
                slot,
                notified_accounts,
                std::iter::once(account),
                notify_stats,
            );
        });
        notify_stats.total_accounts += account_len;
        measure_filter.stop();
        notify_stats.elapsed_filtering_us += measure_filter.as_us() as usize;
    }

    fn notify_filtered_accounts<'a>(
        &self,
        slot: Slot,
        notified_accounts: &mut HashSet<Pubkey>,
        accounts_to_stream: impl Iterator<Item = StoredAccountMeta<'a>>,
        notify_stats: &mut GeyserPluginNotifyAtSnapshotRestoreStats,
    ) {
        let notifier = self.accounts_update_notifier.as_ref().unwrap();
        let mut measure_notify = Measure::start("accountsdb-plugin-notifying-accounts");
        for account in accounts_to_stream {
            let mut measure_pure_notify = Measure::start("accountsdb-plugin-notifying-accounts");
            notifier.notify_account_restore_from_snapshot(slot, &account);
            measure_pure_notify.stop();

            notify_stats.total_pure_notify += measure_pure_notify.as_us() as usize;

            let mut measure_bookkeep = Measure::start("accountsdb-plugin-notifying-bookeeeping");
            notified_accounts.insert(*account.pubkey());
            measure_bookkeep.stop();
            notify_stats.total_pure_bookeeping += measure_bookkeep.as_us() as usize;

            notify_stats.notified_accounts += 1;
        }
        measure_notify.stop();
        notify_stats.elapsed_notifying_us += measure_notify.as_us() as usize;
    }
}

#[cfg(test)]
pub mod tests {
    use {
        crate::{
            account_storage::meta::StoredAccountMeta,
            accounts_db::AccountsDb,
            accounts_update_notifier_interface::{
                AccountsUpdateNotifier, AccountsUpdateNotifierInterface,
            },
        },
        dashmap::DashMap,
        solana_sdk::{
            account::{AccountSharedData, ReadableAccount},
            clock::Slot,
            pubkey::Pubkey,
            transaction::SanitizedTransaction,
        },
        std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    impl AccountsDb {
        pub fn set_geyser_plugin_notifer(&mut self, notifier: Option<AccountsUpdateNotifier>) {
            self.accounts_update_notifier = notifier;
        }
    }

    #[derive(Debug, Default)]
    struct GeyserTestPlugin {
        pub accounts_notified: DashMap<Pubkey, Vec<(Slot, AccountSharedData)>>,
        pub is_startup_done: AtomicBool,
    }

    impl AccountsUpdateNotifierInterface for GeyserTestPlugin {
        /// Notified when an account is updated at runtime, due to transaction activities
        fn notify_account_update(
            &self,
            slot: Slot,
            account: &AccountSharedData,
            _txn: &Option<&SanitizedTransaction>,
            pubkey: &Pubkey,
            _write_version: u64,
        ) {
            self.accounts_notified
                .entry(*pubkey)
                .or_default()
                .push((slot, account.clone()));
        }

        /// Notified when the AccountsDb is initialized at start when restored
        /// from a snapshot.
        fn notify_account_restore_from_snapshot(&self, slot: Slot, account: &StoredAccountMeta) {
            self.accounts_notified
                .entry(*account.pubkey())
                .or_default()
                .push((slot, account.to_account_shared_data()));
        }

        fn notify_end_of_restore_from_snapshot(&self) {
            self.is_startup_done.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_notify_account_restore_from_snapshot_once_per_slot() {
        let mut accounts = AccountsDb::new_single_for_tests();
        // Account with key1 is updated twice in the store -- should only get notified once.
        let key1 = solana_sdk::pubkey::new_rand();
        let mut account1_lamports: u64 = 1;
        let account1 =
            AccountSharedData::new(account1_lamports, 1, AccountSharedData::default().owner());
        let slot0 = 0;
        accounts.store_uncached(slot0, &[(&key1, &account1)]);

        account1_lamports = 2;
        let account1 = AccountSharedData::new(account1_lamports, 1, account1.owner());
        accounts.store_uncached(slot0, &[(&key1, &account1)]);
        let notifier = GeyserTestPlugin::default();

        let key2 = solana_sdk::pubkey::new_rand();
        let account2_lamports: u64 = 100;
        let account2 =
            AccountSharedData::new(account2_lamports, 1, AccountSharedData::default().owner());

        accounts.store_uncached(slot0, &[(&key2, &account2)]);

        let notifier = Arc::new(notifier);
        accounts.set_geyser_plugin_notifer(Some(notifier.clone()));

        accounts.notify_account_restore_from_snapshot();

        assert_eq!(notifier.accounts_notified.get(&key1).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key1).unwrap()[0]
                .1
                .lamports(),
            account1_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key1).unwrap()[0].0, slot0);
        assert_eq!(notifier.accounts_notified.get(&key2).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key2).unwrap()[0]
                .1
                .lamports(),
            account2_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key2).unwrap()[0].0, slot0);

        assert!(notifier.is_startup_done.load(Ordering::Relaxed));
    }

    #[test]
    fn test_notify_account_restore_from_snapshot_once_across_slots() {
        let mut accounts = AccountsDb::new_single_for_tests();
        // Account with key1 is updated twice in two different slots -- should only get notified once.
        // Account with key2 is updated slot0, should get notified once
        // Account with key3 is updated in slot1, should get notified once
        let key1 = solana_sdk::pubkey::new_rand();
        let mut account1_lamports: u64 = 1;
        let account1 =
            AccountSharedData::new(account1_lamports, 1, AccountSharedData::default().owner());
        let slot0 = 0;
        accounts.store_uncached(slot0, &[(&key1, &account1)]);

        let key2 = solana_sdk::pubkey::new_rand();
        let account2_lamports: u64 = 200;
        let account2 =
            AccountSharedData::new(account2_lamports, 1, AccountSharedData::default().owner());
        accounts.store_uncached(slot0, &[(&key2, &account2)]);

        account1_lamports = 2;
        let slot1 = 1;
        let account1 = AccountSharedData::new(account1_lamports, 1, account1.owner());
        accounts.store_uncached(slot1, &[(&key1, &account1)]);
        let notifier = GeyserTestPlugin::default();

        let key3 = solana_sdk::pubkey::new_rand();
        let account3_lamports: u64 = 300;
        let account3 =
            AccountSharedData::new(account3_lamports, 1, AccountSharedData::default().owner());
        accounts.store_uncached(slot1, &[(&key3, &account3)]);

        let notifier = Arc::new(notifier);
        accounts.set_geyser_plugin_notifer(Some(notifier.clone()));

        accounts.notify_account_restore_from_snapshot();

        assert_eq!(notifier.accounts_notified.get(&key1).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key1).unwrap()[0]
                .1
                .lamports(),
            account1_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key1).unwrap()[0].0, slot1);
        assert_eq!(notifier.accounts_notified.get(&key2).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key2).unwrap()[0]
                .1
                .lamports(),
            account2_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key2).unwrap()[0].0, slot0);
        assert_eq!(notifier.accounts_notified.get(&key3).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key3).unwrap()[0]
                .1
                .lamports(),
            account3_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key3).unwrap()[0].0, slot1);
        assert!(notifier.is_startup_done.load(Ordering::Relaxed));
    }

    #[test]
    fn test_notify_account_at_accounts_update() {
        let mut accounts = AccountsDb::new_single_for_tests();

        let notifier = GeyserTestPlugin::default();

        let notifier = Arc::new(notifier);
        accounts.set_geyser_plugin_notifer(Some(notifier.clone()));

        // Account with key1 is updated twice in two different slots -- should only get notified twice.
        // Account with key2 is updated slot0, should get notified once
        // Account with key3 is updated in slot1, should get notified once
        let key1 = solana_sdk::pubkey::new_rand();
        let account1_lamports1: u64 = 1;
        let account1 =
            AccountSharedData::new(account1_lamports1, 1, AccountSharedData::default().owner());
        let slot0 = 0;
        accounts.store_cached((slot0, &[(&key1, &account1)][..]), None);

        let key2 = solana_sdk::pubkey::new_rand();
        let account2_lamports: u64 = 200;
        let account2 =
            AccountSharedData::new(account2_lamports, 1, AccountSharedData::default().owner());
        accounts.store_cached((slot0, &[(&key2, &account2)][..]), None);

        let account1_lamports2 = 2;
        let slot1 = 1;
        let account1 = AccountSharedData::new(account1_lamports2, 1, account1.owner());
        accounts.store_cached((slot1, &[(&key1, &account1)][..]), None);

        let key3 = solana_sdk::pubkey::new_rand();
        let account3_lamports: u64 = 300;
        let account3 =
            AccountSharedData::new(account3_lamports, 1, AccountSharedData::default().owner());
        accounts.store_cached((slot1, &[(&key3, &account3)][..]), None);

        assert_eq!(notifier.accounts_notified.get(&key1).unwrap().len(), 2);
        assert_eq!(
            notifier.accounts_notified.get(&key1).unwrap()[0]
                .1
                .lamports(),
            account1_lamports1
        );
        assert_eq!(notifier.accounts_notified.get(&key1).unwrap()[0].0, slot0);
        assert_eq!(
            notifier.accounts_notified.get(&key1).unwrap()[1]
                .1
                .lamports(),
            account1_lamports2
        );
        assert_eq!(notifier.accounts_notified.get(&key1).unwrap()[1].0, slot1);

        assert_eq!(notifier.accounts_notified.get(&key2).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key2).unwrap()[0]
                .1
                .lamports(),
            account2_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key2).unwrap()[0].0, slot0);
        assert_eq!(notifier.accounts_notified.get(&key3).unwrap().len(), 1);
        assert_eq!(
            notifier.accounts_notified.get(&key3).unwrap()[0]
                .1
                .lamports(),
            account3_lamports
        );
        assert_eq!(notifier.accounts_notified.get(&key3).unwrap()[0].0, slot1);
    }
}
