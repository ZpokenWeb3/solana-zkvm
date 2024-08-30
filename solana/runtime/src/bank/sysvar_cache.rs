#[cfg(test)]
use super::Bank;

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_sdk::{
            feature_set, genesis_config::create_genesis_config, pubkey::Pubkey,
            sysvar::epoch_rewards::EpochRewards,
        },
        std::sync::Arc,
    };

    #[test]
    #[allow(deprecated)]
    fn test_sysvar_cache_initialization() {
        let (genesis_config, _mint_keypair) = create_genesis_config(100_000);
        let bank0 = Arc::new(Bank::new_for_tests(&genesis_config));

        let bank0_sysvar_cache = bank0.transaction_processor.sysvar_cache();
        let bank0_cached_clock = bank0_sysvar_cache.get_clock();
        let bank0_cached_epoch_schedule = bank0_sysvar_cache.get_epoch_schedule();
        let bank0_cached_rent = bank0_sysvar_cache.get_rent();

        assert!(bank0_cached_clock.is_ok());
        assert!(bank0_cached_epoch_schedule.is_ok());
        assert!(bank0_cached_rent.is_ok());
        assert!(bank0_sysvar_cache.get_slot_hashes().is_err());
        assert!(bank0_sysvar_cache.get_epoch_rewards().is_err()); // partitioned epoch reward feature is not enabled

        let bank1_slot = bank0.slot() + 1;
        let bank1 = Arc::new(Bank::new_from_parent(
            bank0.clone(),
            &Pubkey::default(),
            bank1_slot,
        ));

        let bank1_sysvar_cache = bank1.transaction_processor.sysvar_cache();
        let bank1_cached_clock = bank1_sysvar_cache.get_clock();
        let bank1_cached_epoch_schedule = bank1_sysvar_cache.get_epoch_schedule();
        let bank1_cached_rent = bank1_sysvar_cache.get_rent();

        assert!(bank1_cached_clock.is_ok());
        assert!(bank1_cached_epoch_schedule.is_ok());
        assert!(bank1_cached_rent.is_ok());
        assert!(bank1_sysvar_cache.get_slot_hashes().is_ok());
        assert!(bank1_sysvar_cache.get_epoch_rewards().is_err());

        assert_ne!(bank0_cached_clock, bank1_cached_clock);
        assert_eq!(bank0_cached_epoch_schedule, bank1_cached_epoch_schedule);
        assert_eq!(bank0_cached_rent, bank1_cached_rent);

        let bank2_slot = bank1.slot() + 1;
        let bank2 = Bank::new_from_parent(bank1.clone(), &Pubkey::default(), bank2_slot);

        let bank2_sysvar_cache = bank2.transaction_processor.sysvar_cache();
        let bank2_cached_clock = bank2_sysvar_cache.get_clock();
        let bank2_cached_epoch_schedule = bank2_sysvar_cache.get_epoch_schedule();
        let bank2_cached_rent = bank2_sysvar_cache.get_rent();

        assert!(bank2_cached_clock.is_ok());
        assert!(bank2_cached_epoch_schedule.is_ok());
        assert!(bank2_cached_rent.is_ok());
        assert!(bank2_sysvar_cache.get_slot_hashes().is_ok());
        assert!(bank2_sysvar_cache.get_epoch_rewards().is_err()); // partitioned epoch reward feature is not enabled

        assert_ne!(bank1_cached_clock, bank2_cached_clock);
        assert_eq!(bank1_cached_epoch_schedule, bank2_cached_epoch_schedule);
        assert_eq!(bank1_cached_rent, bank2_cached_rent);
        assert_ne!(
            bank1_sysvar_cache.get_slot_hashes(),
            bank2_sysvar_cache.get_slot_hashes(),
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_reset_and_fill_sysvar_cache() {
        let (genesis_config, _mint_keypair) = create_genesis_config(100_000);
        let bank0 = Arc::new(Bank::new_for_tests(&genesis_config));
        let bank1_slot = bank0.slot() + 1;
        let mut bank1 = Bank::new_from_parent(bank0, &Pubkey::default(), bank1_slot);

        let bank1_sysvar_cache = bank1.transaction_processor.sysvar_cache();
        let bank1_cached_clock = bank1_sysvar_cache.get_clock();
        let bank1_cached_epoch_schedule = bank1_sysvar_cache.get_epoch_schedule();
        let bank1_cached_fees = bank1_sysvar_cache.get_fees();
        let bank1_cached_rent = bank1_sysvar_cache.get_rent();
        let bank1_cached_slot_hashes = bank1_sysvar_cache.get_slot_hashes();
        let bank1_cached_epoch_rewards = bank1_sysvar_cache.get_epoch_rewards();

        assert!(bank1_cached_clock.is_ok());
        assert!(bank1_cached_epoch_schedule.is_ok());
        assert!(bank1_cached_rent.is_ok());
        assert!(bank1_cached_slot_hashes.is_ok());
        assert!(bank1_cached_epoch_rewards.is_err());

        drop(bank1_sysvar_cache);
        bank1.transaction_processor.reset_sysvar_cache();

        let bank1_sysvar_cache = bank1.transaction_processor.sysvar_cache();
        assert!(bank1_sysvar_cache.get_clock().is_err());
        assert!(bank1_sysvar_cache.get_epoch_schedule().is_err());
        assert!(bank1_sysvar_cache.get_rent().is_err());
        assert!(bank1_sysvar_cache.get_slot_hashes().is_err());
        assert!(bank1_sysvar_cache.get_epoch_rewards().is_err());

        drop(bank1_sysvar_cache);

        // inject a reward sysvar for test
        bank1.activate_feature(&feature_set::enable_partitioned_epoch_reward::id());
        let num_partitions = 2; // num_partitions is arbitrary and unimportant for this test
        let total_points = 42_000; // total_points is arbitrary for the purposes of this test
        let expected_epoch_rewards = EpochRewards {
            distribution_starting_block_height: 42,
            num_partitions,
            parent_blockhash: bank1.parent().unwrap().last_blockhash(),
            total_points,
            total_rewards: 100,
            distributed_rewards: 10,
            active: true,
        };
        bank1.create_epoch_rewards_sysvar(
            expected_epoch_rewards.total_rewards,
            expected_epoch_rewards.distributed_rewards,
            expected_epoch_rewards.distribution_starting_block_height,
            num_partitions,
            total_points,
        );

        bank1
            .transaction_processor
            .fill_missing_sysvar_cache_entries(&bank1);

        let bank1_sysvar_cache = bank1.transaction_processor.sysvar_cache();
        assert_eq!(bank1_sysvar_cache.get_clock(), bank1_cached_clock);
        assert_eq!(
            bank1_sysvar_cache.get_epoch_schedule(),
            bank1_cached_epoch_schedule
        );
        assert_eq!(bank1_sysvar_cache.get_fees(), bank1_cached_fees);
        assert_eq!(bank1_sysvar_cache.get_rent(), bank1_cached_rent);
        assert_eq!(
            bank1_sysvar_cache.get_slot_hashes(),
            bank1_cached_slot_hashes
        );
        assert_eq!(
            *bank1_sysvar_cache.get_epoch_rewards().unwrap(),
            expected_epoch_rewards,
        );
    }
}
