use std::io::Read;
use risc0_zkvm::guest::env;

use solana_program::hash::Hash;
use solana_sdk::transaction::{SanitizedTransaction};
use svm_core::solana_simulator::SolanaSimulator;
use solana_simulator_types::result::SimulateSolanaRequest;
use solana_simulator_types::result::SimulateSolanaTransactionResult;

fn main() {
    // Read the input data for this application.
    let request: SimulateSolanaRequest = env::read();
    let simulator: SolanaSimulator = env::read();
    let verify = request.verify.unwrap_or(true);
    let mut sanitized_transactions: Vec<SanitizedTransaction> = vec![];
    for tx in request.transactions {
        let sanitized = simulator.sanitize_transaction(tx, verify).unwrap();
        sanitized_transactions.push(sanitized);
    }
    let block_hash: Hash = request.blockhash.clone().into();
    for tx in sanitized_transactions {
        let r = simulator.process_transaction(request.blockhash.into(), &tx).unwrap();
        let error = r.result.err();
        assert_eq!(error.is_none(), true);
    }
    env::commit(&block_hash.to_bytes());
}
