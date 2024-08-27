use crate::solana_simulator::utils::SyncState;
use crate::solana_simulator::SolanaSimulator;
use bincode::Options;
use solana_program::pubkey::Pubkey;
use solana_sdk::transaction::{SanitizedTransaction, Transaction, VersionedTransaction};
use std::collections::HashSet;

#[cfg(feature = "async_enabled")]
use {
    crate::rpc::{config::Config, CloneRpcClient, Rpc, RpcEnum},
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_simulator_types::error::NeonError,
    solana_simulator_types::result::NeonResult,
    solana_simulator_types::result::SimulateSolanaRequest,
    solana_svm::runtime_config::RuntimeConfig,
};

fn address_table_lookups(txs: &[VersionedTransaction]) -> Vec<Pubkey> {
    let mut accounts: HashSet<Pubkey> = HashSet::<Pubkey>::new();
    for tx in txs {
        let Some(address_table_lookups) = tx.message.address_table_lookups() else {
            continue;
        };

        for alt in address_table_lookups {
            accounts.insert(alt.account_key);
        }
    }

    accounts.into_iter().collect()
}

fn account_keys(txs: &[SanitizedTransaction]) -> Vec<Pubkey> {
    let mut accounts: HashSet<Pubkey> = HashSet::<Pubkey>::new();
    for tx in txs {
        let keys = tx.message().account_keys();
        accounts.extend(keys.iter());
    }

    accounts.into_iter().collect()
}

fn decode_transaction(data: &[u8]) -> Result<VersionedTransaction, bincode::Error> {
    let tx_result = bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize::<VersionedTransaction>(data);

    if let Ok(tx) = tx_result {
        return Ok(tx);
    }

    let tx = bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize::<Transaction>(data)?;
    Ok(tx.into())
}

#[cfg(feature = "async_enabled")]
async fn build_rpc(config: &Config) -> Result<RpcEnum, NeonError> {
    Ok(RpcEnum::CloneRpcClient(CloneRpcClient::new_from_config(
        config,
    )))
}

#[cfg(feature = "async_enabled")]
fn runtime_config(request: &SimulateSolanaRequest) -> RuntimeConfig {
    let compute_units = request.compute_units.unwrap_or(1_400_000);
    let heap_size = request.heap_size.unwrap_or(256 * 1024);

    let mut compute_budget = ComputeBudget::new(compute_units);
    compute_budget.heap_size = heap_size;

    RuntimeConfig {
        compute_budget: Some(compute_budget),
        log_messages_bytes_limit: Some(100 * 1024),
        transaction_account_lock_limit: request.account_limit,
    }
}

#[cfg(feature = "async_enabled")]
pub async fn init_simulator(
    rpc: &impl Rpc,
    request: SimulateSolanaRequest,
) -> NeonResult<SolanaSimulator> {
    let verify = request.verify.unwrap_or(true);
    let config = runtime_config(&request);

    let mut simulator = SolanaSimulator::new_with_config(rpc, config, SyncState::Yes).await?;

    // Decode transactions from bytes
    let mut transactions: Vec<VersionedTransaction> = request.transactions.clone();

    // Download ALT
    let alt = address_table_lookups(&transactions);
    simulator.sync_accounts(rpc, &alt).await?;

    // Sanitize transactions (verify tx and decode ALT)
    let mut sanitized_transactions: Vec<SanitizedTransaction> = vec![];
    for tx in transactions {
        let sanitized = simulator.sanitize_transaction(tx, verify)?;
        sanitized_transactions.push(sanitized);
    }

    // Download accounts
    let accounts = account_keys(&sanitized_transactions);
    simulator.sync_accounts(rpc, &accounts).await?;
    Ok(simulator)
}
