//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!

use {
    crate::{block_cost_limits::*, transaction_cost::*},
    log::*,
    solana_compute_budget::compute_budget_processor::{
        process_compute_budget_instructions, DEFAULT_HEAP_COST,
        DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_LIMIT,
    },
    solana_sdk::{
        borsh1::try_from_slice_unchecked,
        compute_budget::{self, ComputeBudgetInstruction},
        feature_set::{self, FeatureSet},
        fee::FeeStructure,
        instruction::CompiledInstruction,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::SystemInstruction,
        system_program,
        transaction::SanitizedTransaction,
    },
};

pub struct CostModel;

impl CostModel {
    pub fn calculate_cost(
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) -> TransactionCost {
        if transaction.is_simple_vote_transaction() {
            TransactionCost::SimpleVote {
                writable_accounts: Self::get_writable_accounts(transaction),
            }
        } else {
            let mut tx_cost = UsageCostDetails::new_with_default_capacity();

            Self::get_signature_cost(&mut tx_cost, transaction);
            Self::get_write_lock_cost(&mut tx_cost, transaction, feature_set);
            Self::get_transaction_cost(&mut tx_cost, transaction, feature_set);
            tx_cost.allocated_accounts_data_size =
                Self::calculate_allocated_accounts_data_size(transaction);

            debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
            TransactionCost::Transaction(tx_cost)
        }
    }

    // Calculate executed transaction CU cost, with actual execution and loaded accounts size
    // costs.
    pub fn calculate_cost_for_executed_transaction(
        transaction: &SanitizedTransaction,
        actual_programs_execution_cost: u64,
        actual_loaded_accounts_data_size_bytes: usize,
        feature_set: &FeatureSet,
    ) -> TransactionCost {
        if transaction.is_simple_vote_transaction() {
            TransactionCost::SimpleVote {
                writable_accounts: Self::get_writable_accounts(transaction),
            }
        } else {
            let mut tx_cost = UsageCostDetails::new_with_default_capacity();

            Self::get_signature_cost(&mut tx_cost, transaction);
            Self::get_write_lock_cost(&mut tx_cost, transaction, feature_set);
            Self::get_instructions_data_cost(&mut tx_cost, transaction);
            tx_cost.allocated_accounts_data_size =
                Self::calculate_allocated_accounts_data_size(transaction);

            tx_cost.programs_execution_cost = actual_programs_execution_cost;
            tx_cost.loaded_accounts_data_size_cost = Self::calculate_loaded_accounts_data_size_cost(
                actual_loaded_accounts_data_size_bytes,
                feature_set,
            );

            TransactionCost::Transaction(tx_cost)
        }
    }

    fn get_signature_cost(tx_cost: &mut UsageCostDetails, transaction: &SanitizedTransaction) {
        let signatures_count_detail = transaction.message().get_signature_details();
        tx_cost.num_transaction_signatures = signatures_count_detail.num_transaction_signatures();
        tx_cost.num_secp256k1_instruction_signatures =
            signatures_count_detail.num_secp256k1_instruction_signatures();
        tx_cost.num_ed25519_instruction_signatures =
            signatures_count_detail.num_ed25519_instruction_signatures();
        tx_cost.signature_cost = signatures_count_detail
            .num_transaction_signatures()
            .saturating_mul(SIGNATURE_COST)
            .saturating_add(
                signatures_count_detail
                    .num_secp256k1_instruction_signatures()
                    .saturating_mul(SECP256K1_VERIFY_COST),
            )
            .saturating_add(
                signatures_count_detail
                    .num_ed25519_instruction_signatures()
                    .saturating_mul(ED25519_VERIFY_COST),
            );
    }

    fn get_writable_accounts(transaction: &SanitizedTransaction) -> Vec<Pubkey> {
        let message = transaction.message();
        message
            .account_keys()
            .iter()
            .enumerate()
            .filter_map(|(i, k)| {
                if message.is_writable(i) {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_write_lock_cost(
        tx_cost: &mut UsageCostDetails,
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) {
        tx_cost.writable_accounts = Self::get_writable_accounts(transaction);
        let num_write_locks =
            if feature_set.is_active(&feature_set::cost_model_requested_write_lock_cost::id()) {
                transaction.message().num_write_locks()
            } else {
                tx_cost.writable_accounts.len() as u64
            };
        tx_cost.write_lock_cost = WRITE_LOCK_UNITS.saturating_mul(num_write_locks);
    }

    fn get_transaction_cost(
        tx_cost: &mut UsageCostDetails,
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) {
        let mut programs_execution_costs = 0u64;
        let mut loaded_accounts_data_size_cost = 0u64;
        let mut data_bytes_len_total = 0u64;
        let mut compute_unit_limit_is_set = false;
        let mut has_user_space_instructions = false;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            let ix_execution_cost =
                if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                    *builtin_cost
                } else {
                    has_user_space_instructions = true;
                    u64::from(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT)
                };

            programs_execution_costs = programs_execution_costs
                .saturating_add(ix_execution_cost)
                .min(u64::from(MAX_COMPUTE_UNIT_LIMIT));

            data_bytes_len_total =
                data_bytes_len_total.saturating_add(instruction.data.len() as u64);

            if compute_budget::check_id(program_id) {
                if let Ok(ComputeBudgetInstruction::SetComputeUnitLimit(_)) =
                    try_from_slice_unchecked(&instruction.data)
                {
                    compute_unit_limit_is_set = true;
                }
            }
        }

        // if failed to process compute_budget instructions, the transaction will not be executed
        // by `bank`, therefore it should be considered as no execution cost by cost model.
        match process_compute_budget_instructions(transaction.message().program_instructions_iter())
        {
            Ok(compute_budget_limits) => {
                // if tx contained user-space instructions and a more accurate estimate available correct it,
                // where "user-space instructions" must be specifically checked by
                // 'compute_unit_limit_is_set' flag, because compute_budget does not distinguish
                // builtin and bpf instructions when calculating default compute-unit-limit. (see
                // compute_budget.rs test `test_process_mixed_instructions_without_compute_budget`)
                if has_user_space_instructions && compute_unit_limit_is_set {
                    programs_execution_costs = u64::from(compute_budget_limits.compute_unit_limit);
                }

                loaded_accounts_data_size_cost = Self::calculate_loaded_accounts_data_size_cost(
                    usize::try_from(compute_budget_limits.loaded_accounts_bytes).unwrap(),
                    feature_set,
                );
            }
            Err(_) => {
                programs_execution_costs = 0;
            }
        }

        tx_cost.programs_execution_cost = programs_execution_costs;
        tx_cost.loaded_accounts_data_size_cost = loaded_accounts_data_size_cost;
        tx_cost.data_bytes_cost = data_bytes_len_total / INSTRUCTION_DATA_BYTES_COST;
    }

    fn get_instructions_data_cost(
        tx_cost: &mut UsageCostDetails,
        transaction: &SanitizedTransaction,
    ) {
        let ix_data_bytes_len_total: u64 = transaction
            .message()
            .instructions()
            .iter()
            .map(|instruction| instruction.data.len() as u64)
            .sum();

        tx_cost.data_bytes_cost = ix_data_bytes_len_total / INSTRUCTION_DATA_BYTES_COST;
    }

    pub fn calculate_loaded_accounts_data_size_cost(
        loaded_accounts_data_size: usize,
        _feature_set: &FeatureSet,
    ) -> u64 {
        FeeStructure::calculate_memory_usage_cost(loaded_accounts_data_size, DEFAULT_HEAP_COST)
    }

    fn calculate_account_data_size_on_deserialized_system_instruction(
        instruction: SystemInstruction,
    ) -> u64 {
        match instruction {
            SystemInstruction::CreateAccount {
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::CreateAccountWithSeed {
                base: _base,
                seed: _seed,
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::Allocate { space } => space,
            SystemInstruction::AllocateWithSeed {
                base: _base,
                seed: _seed,
                space,
                owner: _owner,
            } => space,
            _ => 0,
        }
    }

    fn calculate_account_data_size_on_instruction(
        program_id: &Pubkey,
        instruction: &CompiledInstruction,
    ) -> u64 {
        if program_id == &system_program::id() {
            if let Ok(instruction) = limited_deserialize(&instruction.data) {
                return Self::calculate_account_data_size_on_deserialized_system_instruction(
                    instruction,
                );
            }
        }
        0
    }

    /// eventually, potentially determine account data size of all writable accounts
    /// at the moment, calculate account data size of account creation
    fn calculate_allocated_accounts_data_size(transaction: &SanitizedTransaction) -> u64 {
        transaction
            .message()
            .program_instructions_iter()
            .map(|(program_id, instruction)| {
                Self::calculate_account_data_size_on_instruction(program_id, instruction)
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_sdk::{
            compute_budget::{self, ComputeBudgetInstruction},
            fee::ACCOUNT_DATA_COST_PAGE_SIZE,
            hash::Hash,
            instruction::{CompiledInstruction, Instruction},
            message::Message,
            signature::{Keypair, Signer},
            system_instruction::{self},
            system_program, system_transaction,
            transaction::Transaction,
        },
    };

    fn test_setup() -> (Keypair, Hash) {
        solana_logger::setup();
        (Keypair::new(), Hash::new_unique())
    }

    #[test]
    fn test_cost_model_data_len_cost() {
        let lamports = 0;
        let owner = Pubkey::default();
        let seed = String::default();
        let space = 100;
        let base = Pubkey::default();
        for instruction in [
            SystemInstruction::CreateAccount {
                lamports,
                space,
                owner,
            },
            SystemInstruction::CreateAccountWithSeed {
                base,
                seed: seed.clone(),
                lamports,
                space,
                owner,
            },
            SystemInstruction::Allocate { space },
            SystemInstruction::AllocateWithSeed {
                base,
                seed,
                space,
                owner,
            },
        ] {
            assert_eq!(
                space,
                CostModel::calculate_account_data_size_on_deserialized_system_instruction(
                    instruction
                )
            );
        }
        assert_eq!(
            0,
            CostModel::calculate_account_data_size_on_deserialized_system_instruction(
                SystemInstruction::TransferWithSeed {
                    lamports,
                    from_seed: String::default(),
                    from_owner: Pubkey::default(),
                }
            )
        );
    }

    #[test]
    fn test_cost_model_simple_transaction() {
        let (mint_keypair, start_hash) = test_setup();

        let keypair = Keypair::new();
        let simple_transaction = SanitizedTransaction::from_transaction_for_tests(
            system_transaction::transfer(&mint_keypair, &keypair.pubkey(), 2, start_hash),
        );
        debug!(
            "system_transaction simple_transaction {:?}",
            simple_transaction
        );

        // expected cost for one system transfer instructions
        let expected_execution_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(
            &mut tx_cost,
            &simple_transaction,
            &FeatureSet::all_enabled(),
        );
        assert_eq!(*expected_execution_cost, tx_cost.programs_execution_cost);
        assert_eq!(3, tx_cost.data_bytes_cost);
    }

    #[test]
    fn test_cost_model_token_transaction() {
        let (mint_keypair, start_hash) = test_setup();

        let instructions = vec![CompiledInstruction::new(3, &(), vec![1, 2, 0])];
        let tx = Transaction::new_with_compiled_instructions(
            &[&mint_keypair],
            &[
                solana_sdk::pubkey::new_rand(),
                solana_sdk::pubkey::new_rand(),
            ],
            start_hash,
            vec![Pubkey::new_unique()],
            instructions,
        );
        let token_transaction = SanitizedTransaction::from_transaction_for_tests(tx);
        debug!("token_transaction {:?}", token_transaction);

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(
            &mut tx_cost,
            &token_transaction,
            &FeatureSet::all_enabled(),
        );
        assert_eq!(
            DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT as u64,
            tx_cost.programs_execution_cost
        );
        assert_eq!(0, tx_cost.data_bytes_cost);
    }

    #[test]
    fn test_cost_model_demoted_write_lock() {
        let (mint_keypair, start_hash) = test_setup();

        // Cannot write-lock the system program, it will be demoted when taking locks.
        // However, the cost should be calculated as if it were taken.
        let simple_transaction = SanitizedTransaction::from_transaction_for_tests(
            system_transaction::transfer(&mint_keypair, &system_program::id(), 2, start_hash),
        );

        // Feature not enabled - write lock is demoted and does not count towards cost
        {
            let tx_cost = CostModel::calculate_cost(&simple_transaction, &FeatureSet::default());
            assert_eq!(WRITE_LOCK_UNITS, tx_cost.write_lock_cost());
            assert_eq!(1, tx_cost.writable_accounts().len());
        }

        // Feature enabled - write lock is demoted but still counts towards cost
        {
            let tx_cost =
                CostModel::calculate_cost(&simple_transaction, &FeatureSet::all_enabled());
            assert_eq!(2 * WRITE_LOCK_UNITS, tx_cost.write_lock_cost());
            assert_eq!(1, tx_cost.writable_accounts().len());
        }
    }

    #[test]
    fn test_cost_model_compute_budget_transaction() {
        let (mint_keypair, start_hash) = test_setup();

        let instructions = vec![
            CompiledInstruction::new(3, &(), vec![1, 2, 0]),
            CompiledInstruction::new_from_raw_parts(
                4,
                ComputeBudgetInstruction::SetComputeUnitLimit(12_345)
                    .pack()
                    .unwrap(),
                vec![],
            ),
        ];
        let tx = Transaction::new_with_compiled_instructions(
            &[&mint_keypair],
            &[
                solana_sdk::pubkey::new_rand(),
                solana_sdk::pubkey::new_rand(),
            ],
            start_hash,
            vec![Pubkey::new_unique(), compute_budget::id()],
            instructions,
        );
        let token_transaction = SanitizedTransaction::from_transaction_for_tests(tx);

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(
            &mut tx_cost,
            &token_transaction,
            &FeatureSet::all_enabled(),
        );
        // If cu-limit is specified, that would the cost for all programs
        assert_eq!(12_345, tx_cost.programs_execution_cost);
        assert_eq!(1, tx_cost.data_bytes_cost);
    }

    #[test]
    fn test_cost_model_with_failed_compute_budget_transaction() {
        let (mint_keypair, start_hash) = test_setup();

        let instructions = vec![
            CompiledInstruction::new(3, &(), vec![1, 2, 0]),
            CompiledInstruction::new_from_raw_parts(
                4,
                ComputeBudgetInstruction::SetComputeUnitLimit(12_345)
                    .pack()
                    .unwrap(),
                vec![],
            ),
            // to trigger `duplicate_instruction_error` error
            CompiledInstruction::new_from_raw_parts(
                4,
                ComputeBudgetInstruction::SetComputeUnitLimit(1_000)
                    .pack()
                    .unwrap(),
                vec![],
            ),
        ];
        let tx = Transaction::new_with_compiled_instructions(
            &[&mint_keypair],
            &[
                solana_sdk::pubkey::new_rand(),
                solana_sdk::pubkey::new_rand(),
            ],
            start_hash,
            vec![Pubkey::new_unique(), compute_budget::id()],
            instructions,
        );
        let token_transaction = SanitizedTransaction::from_transaction_for_tests(tx);

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(
            &mut tx_cost,
            &token_transaction,
            &FeatureSet::all_enabled(),
        );
        assert_eq!(0, tx_cost.programs_execution_cost);
    }

    #[test]
    fn test_cost_model_transaction_many_transfer_instructions() {
        let (mint_keypair, start_hash) = test_setup();

        let key1 = solana_sdk::pubkey::new_rand();
        let key2 = solana_sdk::pubkey::new_rand();
        let instructions =
            system_instruction::transfer_many(&mint_keypair.pubkey(), &[(key1, 1), (key2, 1)]);
        let message = Message::new(&instructions, Some(&mint_keypair.pubkey()));
        let tx = SanitizedTransaction::from_transaction_for_tests(Transaction::new(
            &[&mint_keypair],
            message,
            start_hash,
        ));
        debug!("many transfer transaction {:?}", tx);

        // expected cost for two system transfer instructions
        let program_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();
        let expected_cost = program_cost * 2;

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(&mut tx_cost, &tx, &FeatureSet::all_enabled());
        assert_eq!(expected_cost, tx_cost.programs_execution_cost);
        assert_eq!(6, tx_cost.data_bytes_cost);
    }

    #[test]
    fn test_cost_model_message_many_different_instructions() {
        let (mint_keypair, start_hash) = test_setup();

        // construct a transaction with multiple random instructions
        let key1 = solana_sdk::pubkey::new_rand();
        let key2 = solana_sdk::pubkey::new_rand();
        let prog1 = solana_sdk::pubkey::new_rand();
        let prog2 = solana_sdk::pubkey::new_rand();
        let instructions = vec![
            CompiledInstruction::new(3, &(), vec![0, 1]),
            CompiledInstruction::new(4, &(), vec![0, 2]),
        ];
        let tx = SanitizedTransaction::from_transaction_for_tests(
            Transaction::new_with_compiled_instructions(
                &[&mint_keypair],
                &[key1, key2],
                start_hash,
                vec![prog1, prog2],
                instructions,
            ),
        );
        debug!("many random transaction {:?}", tx);

        let expected_cost = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT as u64 * 2;
        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(&mut tx_cost, &tx, &FeatureSet::all_enabled());
        assert_eq!(expected_cost, tx_cost.programs_execution_cost);
        assert_eq!(0, tx_cost.data_bytes_cost);
    }

    #[test]
    fn test_cost_model_sort_message_accounts_by_type() {
        // construct a transaction with two random instructions with same signer
        let signer1 = Keypair::new();
        let signer2 = Keypair::new();
        let key1 = Pubkey::new_unique();
        let key2 = Pubkey::new_unique();
        let prog1 = Pubkey::new_unique();
        let prog2 = Pubkey::new_unique();
        let instructions = vec![
            CompiledInstruction::new(4, &(), vec![0, 2]),
            CompiledInstruction::new(5, &(), vec![1, 3]),
        ];
        let tx = SanitizedTransaction::from_transaction_for_tests(
            Transaction::new_with_compiled_instructions(
                &[&signer1, &signer2],
                &[key1, key2],
                Hash::new_unique(),
                vec![prog1, prog2],
                instructions,
            ),
        );

        let tx_cost = CostModel::calculate_cost(&tx, &FeatureSet::all_enabled());
        assert_eq!(2 + 2, tx_cost.writable_accounts().len());
        assert_eq!(signer1.pubkey(), tx_cost.writable_accounts()[0]);
        assert_eq!(signer2.pubkey(), tx_cost.writable_accounts()[1]);
        assert_eq!(key1, tx_cost.writable_accounts()[2]);
        assert_eq!(key2, tx_cost.writable_accounts()[3]);
    }

    #[test]
    fn test_cost_model_calculate_cost_all_default() {
        let (mint_keypair, start_hash) = test_setup();
        let tx = SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
            &mint_keypair,
            &Keypair::new().pubkey(),
            2,
            start_hash,
        ));

        let expected_account_cost = WRITE_LOCK_UNITS * 2;
        let expected_execution_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();
        const DEFAULT_PAGE_COST: u64 = 8;
        let expected_loaded_accounts_data_size_cost =
            solana_compute_budget::compute_budget_processor::MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES
                as u64
                / ACCOUNT_DATA_COST_PAGE_SIZE
                * DEFAULT_PAGE_COST;

        let tx_cost = CostModel::calculate_cost(&tx, &FeatureSet::all_enabled());
        assert_eq!(expected_account_cost, tx_cost.write_lock_cost());
        assert_eq!(*expected_execution_cost, tx_cost.programs_execution_cost());
        assert_eq!(2, tx_cost.writable_accounts().len());
        assert_eq!(
            expected_loaded_accounts_data_size_cost,
            tx_cost.loaded_accounts_data_size_cost()
        );
    }

    #[test]
    fn test_cost_model_calculate_cost_with_limit() {
        let (mint_keypair, start_hash) = test_setup();
        let to_keypair = Keypair::new();
        let data_limit = 32 * 1024u32;
        let tx =
            SanitizedTransaction::from_transaction_for_tests(Transaction::new_signed_with_payer(
                &[
                    system_instruction::transfer(&mint_keypair.pubkey(), &to_keypair.pubkey(), 2),
                    ComputeBudgetInstruction::set_loaded_accounts_data_size_limit(data_limit),
                ],
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                start_hash,
            ));

        let feature_set = FeatureSet::all_enabled();
        let expected_account_cost = WRITE_LOCK_UNITS * 2;
        let expected_execution_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap()
            + BUILT_IN_INSTRUCTION_COSTS
                .get(&compute_budget::id())
                .unwrap();
        let expected_loaded_accounts_data_size_cost = (data_limit as u64) / (32 * 1024) * 8;

        let tx_cost = CostModel::calculate_cost(&tx, &feature_set);
        assert_eq!(expected_account_cost, tx_cost.write_lock_cost());
        assert_eq!(expected_execution_cost, tx_cost.programs_execution_cost());
        assert_eq!(2, tx_cost.writable_accounts().len());
        assert_eq!(
            expected_loaded_accounts_data_size_cost,
            tx_cost.loaded_accounts_data_size_cost()
        );
    }

    #[test]
    fn test_transaction_cost_with_mix_instruction_without_compute_budget() {
        let (mint_keypair, start_hash) = test_setup();

        let transaction =
            SanitizedTransaction::from_transaction_for_tests(Transaction::new_signed_with_payer(
                &[
                    Instruction::new_with_bincode(Pubkey::new_unique(), &0_u8, vec![]),
                    system_instruction::transfer(&mint_keypair.pubkey(), &Pubkey::new_unique(), 2),
                ],
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                start_hash,
            ));
        // transaction has one builtin instruction, and one bpf instruction, no ComputeBudget::compute_unit_limit
        let expected_builtin_cost = *BUILT_IN_INSTRUCTION_COSTS
            .get(&solana_system_program::id())
            .unwrap();
        let expected_bpf_cost = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(&mut tx_cost, &transaction, &FeatureSet::all_enabled());

        assert_eq!(
            expected_builtin_cost + expected_bpf_cost as u64,
            tx_cost.programs_execution_cost
        );
    }

    #[test]
    fn test_transaction_cost_with_mix_instruction_with_cu_limit() {
        let (mint_keypair, start_hash) = test_setup();

        let transaction =
            SanitizedTransaction::from_transaction_for_tests(Transaction::new_signed_with_payer(
                &[
                    system_instruction::transfer(&mint_keypair.pubkey(), &Pubkey::new_unique(), 2),
                    ComputeBudgetInstruction::set_compute_unit_limit(12_345),
                ],
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                start_hash,
            ));
        // transaction has one builtin instruction, and one ComputeBudget::compute_unit_limit
        let expected_cost = *BUILT_IN_INSTRUCTION_COSTS
            .get(&solana_system_program::id())
            .unwrap()
            + BUILT_IN_INSTRUCTION_COSTS
                .get(&compute_budget::id())
                .unwrap();

        let mut tx_cost = UsageCostDetails::default();
        CostModel::get_transaction_cost(&mut tx_cost, &transaction, &FeatureSet::all_enabled());

        assert_eq!(expected_cost, tx_cost.programs_execution_cost);
    }
}
