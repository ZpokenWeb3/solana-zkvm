#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Program Account error")]
    ProgramAccountError,
    #[cfg(feature = "async_enabled")]
    #[error("Rpc Client error {0:?}")]
    RpcClientError(#[from] solana_client::client_error::ClientError),
    #[error("Bincode error {0:?}")]
    BincodeError(#[from] bincode::Error),
    #[error("Transaction error {0:?}")]
    TransactionError(#[from] solana_sdk::transaction::TransactionError),
    #[error("Instruction error {0:?}")]
    InstructionError(#[from] solana_sdk::instruction::InstructionError),
    #[error("Invalid ALT")]
    InvalidALT,
}