use std::io::Read;

use risc0_zkvm::guest::env;
use solana_program::hash::Hash;
use solana_sdk::transaction::SanitizedTransaction;

use svm_core::HostInput;

fn main() {
    // Read the input data for this application.
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();
    let input: HostInput = bincode::deserialize(&input_bytes).unwrap();
    let verify = input.request.verify.unwrap_or(true);
    let mut sanitized_transactions: Vec<SanitizedTransaction> = vec![];
    for tx in input.request.transactions {
        let sanitized = input.simulator.sanitize_transaction(tx, verify).unwrap();
        sanitized_transactions.push(sanitized);
    }
    let block_hash: Hash = input.request.blockhash.clone().into();
    for tx in sanitized_transactions {
        let r = input.simulator.process_transaction(input.request.blockhash.into(), &tx).unwrap();
        let error = r.result.err();
        assert_eq!(error.is_none(), true);
    }
    env::commit(&block_hash.to_bytes());
}
