use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use risc0_zkvm::guest::env;
use svm_core::integration::{create_executable_environment, prepare_transactions, register_builtins};
use svm_core::mock_bank::{MockBankCallback, MockForkGraph};
use solana_sdk::account::ReadableAccount;
use solana_sdk::signature::{Signer};
use solana_sdk::transaction::{TransactionError};
use solana_svm::transaction_processor::{ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig, TransactionProcessingEnvironment};
use solana_svm::transaction_results::TransactionExecutionResult;

const DEPLOYMENT_SLOT: u64 = 0;
const EXECUTION_SLOT: u64 = 5; // The execution slot must be greater than the deployment slot
const DEPLOYMENT_EPOCH: u64 = 0;
const EXECUTION_EPOCH: u64 = 2;

fn main() {
    // TODO: Implement logic to input program bytes

    // read the input
    let mut input: Vec<u8> = env::read();
    let time: i64 = env::read();
    //
    let mut mock_bank = MockBankCallback::default();
    let (transactions, check_results) = prepare_transactions(&mut mock_bank, &mut input);
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
        time
    );
    batch_processor.fill_missing_sysvar_cache_entries(&mock_bank);
    register_builtins(&mock_bank, &batch_processor);

    let processing_config = TransactionProcessingConfig {
        recording_config: ExecutionRecordingConfig {
            enable_log_recording: true,
            enable_return_data_recording: true,
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
    log::info!("Result {:?}", result.execution_results);

    env::commit(&input);
}
