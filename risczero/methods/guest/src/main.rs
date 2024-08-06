use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use risc0_zkvm::guest::env;
use svm_core::integration::{create_executable_environment, MockForkGraph, prepare_transactions, register_builtins};
use svm_core::mock_bank::MockBankCallback;
use solana_program::pubkey::Pubkey;
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig, TransactionProcessingEnvironment};

const BPF_LOADER_NAME: &str = "solana_bpf_loader_upgradeable_program";
const SYSTEM_PROGRAM_NAME: &str = "system_program";
const DEPLOYMENT_SLOT: u64 = 0;
const EXECUTION_SLOT: u64 = 5; // The execution slot must be greater than the deployment slot
const DEPLOYMENT_EPOCH: u64 = 0;
const EXECUTION_EPOCH: u64 = 2; // The execution epoch must be greater than the deployment epoch

fn main() {
    // TODO: Implement logic to input program bytes

    // read the input
    let input: Vec<u8> = env::read();
    let time: i64 = env::read();
    let mut mock_bank = MockBankCallback::default();
    let program_id = Pubkey::new_from_array([4u8; 32]);
    let sender = Pubkey::new_from_array([1u8; 32]);
    let recipient = Pubkey::new_from_array([2u8; 32]);
    let fee_payer = Pubkey::new_from_array([3u8; 32]);
    let (transactions, check_results) = prepare_transactions(
        &mut mock_bank,
        input,
        program_id,
        sender,
        recipient,
        fee_payer);
    let batch_processor = TransactionBatchProcessor::<MockForkGraph>::new(
        EXECUTION_SLOT,
        EXECUTION_EPOCH,
        HashSet::new(),
    );
    let fork_graph = Arc::new(RwLock::new(MockForkGraph {}));
    //
    create_executable_environment(
        fork_graph.clone(),
        &mut mock_bank,
        &mut batch_processor.program_cache.write().unwrap(),
        time,
    );
    batch_processor.fill_missing_sysvar_cache_entries(&mock_bank);
    register_builtins(&mock_bank, &batch_processor);

    let processing_config = TransactionProcessingConfig {
        recording_config: ExecutionRecordingConfig {
            enable_log_recording: true,
            enable_return_data_recording: false,
            enable_cpi_recording: false,
        },
        ..Default::default()
    };

    let result = batch_processor.load_and_execute_sanitized_transactions(
        &mock_bank,
        &transactions,
        check_results,
        &TransactionProcessingEnvironment::default(),
        &processing_config,
    );
    println!("Result {:?}", result.execution_results);
    let temp_output: u32 = 1;
    env::commit(&temp_output);
}
