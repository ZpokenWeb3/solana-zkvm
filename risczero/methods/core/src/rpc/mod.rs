pub mod config;
pub mod validator_client;

pub use validator_client::CloneRpcClient;

use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use solana_cli::cli::CliError;
use solana_client::client_error::Result as ClientResult;
use solana_sdk::message::Message;
use solana_sdk::native_token::lamports_to_sol;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::VersionedTransaction;
use solana_sdk::{
    account::Account,
    clock::{Slot, UnixTimestamp},
    pubkey::Pubkey,
};

use crate::config_simulator::ConfigSimulator;
use crate::config_simulator::BuildConfigSimulator;


#[async_trait(?Send)]
#[enum_dispatch]
pub trait Rpc {
    async fn get_account(&self, key: &Pubkey) -> ClientResult<Option<Account>>;
    async fn get_multiple_accounts(&self, pubkeys: &[Pubkey])
        -> ClientResult<Vec<Option<Account>>>;
    async fn get_block_time(&self, slot: Slot) -> ClientResult<UnixTimestamp>;
    async fn get_slot(&self) -> ClientResult<Slot>;
    async fn get_deactivated_solana_features(&self) -> ClientResult<Vec<Pubkey>>;
    async fn get_transaction(
        &self,
        signature: &Signature,
    ) -> ClientResult<Option<VersionedTransaction>>;
}

#[enum_dispatch(BuildConfigSimulator, Rpc)]
pub enum RpcEnum {
    CloneRpcClient,
}

macro_rules! e {
    ($mes:expr) => {
        ClientError::from(ClientErrorKind::Custom(format!("{}", $mes)))
    };
    ($mes:expr, $error:expr) => {
        ClientError::from(ClientErrorKind::Custom(format!("{}: {:?}", $mes, $error)))
    };
    ($mes:expr, $error:expr, $arg:expr) => {
        ClientError::from(ClientErrorKind::Custom(format!(
            "{}, {:?}: {:?}",
            $mes, $error, $arg
        )))
    };
}

pub(crate) use e;
use solana_simulator_types::error::NeonError;
use solana_simulator_types::result::NeonResult;

pub(crate) async fn check_account_for_fee(
    rpc_client: &CloneRpcClient,
    account_pubkey: &Pubkey,
    message: &Message,
) -> NeonResult<()> {
    let fee = rpc_client.get_fee_for_message(message).await?;
    let balance = rpc_client.get_balance(account_pubkey).await?;
    if balance != 0 && balance >= fee {
        return Ok(());
    }

    Err(NeonError::CliError(CliError::InsufficientFundsForFee(
        lamports_to_sol(fee),
        *account_pubkey,
    )))
}
