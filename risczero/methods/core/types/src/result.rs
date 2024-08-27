use serde_with::serde::{Deserialize, Serialize};
use serde_with::serde_as;
use solana_sdk::inner_instruction::InnerInstructions;
use solana_sdk::transaction::VersionedTransaction;
use solana_sdk::transaction_context::{TransactionAccount, TransactionReturnData};
use solana_svm::transaction_processor::TransactionLogMessages;

#[cfg(feature = "async_enabled")]
use crate::error::NeonError;

#[cfg(feature = "async_enabled")]
pub type NeonResult<T> = Result<T, NeonError>;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct SimulateSolanaRequest {
    pub compute_units: Option<u64>,
    pub heap_size: Option<u32>,
    pub account_limit: Option<usize>,
    pub verify: Option<bool>,
    pub blockhash: [u8; 32],
    pub transactions: Vec<VersionedTransaction>,
    pub id: Option<String>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct SimulateSolanaResponse {
    pub transactions: Vec<SimulateSolanaTransactionResult>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct SimulateSolanaTransactionResult {
    pub error: Option<solana_sdk::transaction::TransactionError>,
    pub logs: Vec<String>,
    pub executed_units: u64,
}

pub struct TransactionSimulationResult {
    pub result: solana_sdk::transaction::Result<()>,
    pub logs: TransactionLogMessages,
    pub post_simulation_accounts: Vec<TransactionAccount>,
    pub units_consumed: u64,
    pub return_data: Option<TransactionReturnData>,
    pub inner_instructions: Option<Vec<InnerInstructions>>,
}
