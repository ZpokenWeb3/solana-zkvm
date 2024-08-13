use std::collections::HashSet;
use bincode::Options;
use solana_program::pubkey::Pubkey;
use solana_sdk::transaction::{SanitizedTransaction, Transaction, VersionedTransaction};

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