use risc0_zkvm::guest::env;

use solana_program::hash::Hash;
use solana_sdk::transaction::VersionedTransaction;
use svm_core::solana_simulator::SolanaSimulator;

fn main() {
    let input: Vec<u8> = env::read();
    let simulator: SolanaSimulator = env::read();
    let tx: VersionedTransaction = bincode::deserialize(&input).unwrap();
    let sanitized = simulator.sanitize_transaction(tx, false).unwrap();
    let hash: Hash = Hash::default();
    println!("Result: {:?}", simulator.process_transaction(hash, &sanitized).unwrap().result);
    let temp_output: u32 = 1;
    env::commit(&temp_output);
}
