pub mod validator_client;
pub mod config;

use async_trait::async_trait;
use solana_program::clock::{Slot, UnixTimestamp};
use solana_program::pubkey::Pubkey;

use solana_client::client_error::Result as ClientResult;
use solana_sdk::account::Account;

#[async_trait(?Send)]
pub trait Rpc {
    async fn get_account(&self, key: &Pubkey) -> ClientResult<Option<Account>>;
    async fn get_multiple_accounts(&self, pubkeys: &[Pubkey])
                                   -> ClientResult<Vec<Option<Account>>>;
    async fn get_block_time(&self, slot: Slot) -> ClientResult<UnixTimestamp>;
    async fn get_slot(&self) -> ClientResult<Slot>;
    async fn get_deactivated_solana_features(&self) -> ClientResult<Vec<Pubkey>>;
}

pub enum RpcEnum {
    CloneRpcClient,
    CallDbClient,
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