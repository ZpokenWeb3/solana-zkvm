use risc0_zkvm::guest::env;

use solana_program::hash::Hash;
use solana_sdk::transaction::{SanitizedTransaction};
use svm_core::solana_simulator::SolanaSimulator;
use solana_simulator_types::result::SimulateSolanaRequest;
use solana_simulator_types::result::SimulateSolanaTransactionResult;

fn main() {
    let request: SimulateSolanaRequest = env::read();
    let simulator: SolanaSimulator = env::read();
    let verify = request.verify.unwrap_or(true);
    let mut sanitized_transactions: Vec<SanitizedTransaction> = vec![];
    for tx in request.transactions {
        let sanitized = simulator.sanitize_transaction(tx, verify).unwrap();
        sanitized_transactions.push(sanitized);
    }
    let mut results = Vec::new();
    for tx in sanitized_transactions {
        let r = simulator.process_transaction(request.blockhash.into(), &tx).unwrap();
        results.push(SimulateSolanaTransactionResult {
            error: r.result.err(),
            logs: r.logs,
            executed_units: r.units_consumed,
        });
    }
    println!("Result: {:?}", results);

    let temp_output: u32 = 1;
    env::commit(&temp_output);
}
