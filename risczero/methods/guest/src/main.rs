use risc0_zkvm::guest::env;

use solana_program::hash::Hash;
use solana_sdk::transaction::VersionedTransaction;
use svm_core::solana_simulator::SolanaSimulator;

fn main() {
    let input: Vec<u8> = env::read();
    let simulator: SolanaSimulator = env::read();
    let tx: VersionedTransaction = bincode::deserialize(&input).unwrap();
    let sanitized = simulator.sanitize_transaction(tx, true).unwrap();
    let hash: Hash = Hash::default();
    println!("BLOCK HASH: {:?}", hash);
    println!("BLOCK HASH in TX: {:?}", sanitized.message().recent_blockhash());
    let simulation_result = simulator.process_transaction(hash, &sanitized).unwrap();
    assert_eq!(true, simulation_result.result.is_ok());
    println!("Units consumed: {:?}", simulation_result.units_consumed);
    let temp_output: u32 = 1;
    env::commit(&temp_output);
}
