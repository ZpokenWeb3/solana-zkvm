#[cfg(test)]
mod tests {
    use methods::CUSTOM_METHOD_ELF;
    use risc0_zkvm::{get_prover_server, ExecutorEnv, ProverOpts};
    use solana_simulator_types::result::SimulateSolanaRequest;
    use std::fs::File;
    use std::{env, io};
    use std::io::Read;
    use std::path::PathBuf;
    use solana_sdk::hash::Hash;
    use svm_core::solana_simulator::SolanaSimulator;

    fn deserialize_buffer_from_file(file_path: PathBuf) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn get_testdata_path(filename: &str) -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir).join("testdata").join(filename)
    }

    #[test]
    fn proves_transaction() {
        env::set_var("RISC0_DEV_MODE", "1");
        env::set_var("RUST_LOG", "info");

        let request_path = get_testdata_path("coinflip/request.bin");
        let request_buffer = deserialize_buffer_from_file(request_path).unwrap();
        let request: SimulateSolanaRequest = bincode::deserialize(&request_buffer).expect("Failed to deserialize request");

        let simulator_path = get_testdata_path("coinflip/simulator.bin");
        let simulator_buffer = deserialize_buffer_from_file(simulator_path).unwrap();
        let simulator: SolanaSimulator = bincode::deserialize(&simulator_buffer).expect("Failed to deserialize simulator");
        let env = ExecutorEnv::builder()
            .write(&request)
            .unwrap()
            .write(&simulator)
            .unwrap()
            .build()
            .unwrap();
        let prover_opts = ProverOpts::fast();
        let prover = get_prover_server(&prover_opts).unwrap();
        let receipt = prover
            .prove(env, CUSTOM_METHOD_ELF)
            .unwrap()
            .receipt;
        let journal = receipt.journal.bytes.clone();
    }

    #[test]
    #[should_panic(expected = "TransactionError(SignatureFailure)")]
    fn rejects_incorrect_transaction() {
        env::set_var("RISC0_DEV_MODE", "1");
        env::set_var("RUST_LOG", "info");

        let request_path = get_testdata_path("coinflip/request.bin");
        let request_buffer = deserialize_buffer_from_file(request_path).unwrap();
        let mut request: SimulateSolanaRequest = bincode::deserialize(&request_buffer).expect("Failed to deserialize request");

        let simulator_path = get_testdata_path("coinflip/simulator.bin");
        let simulator_buffer = deserialize_buffer_from_file(simulator_path).unwrap();
        let simulator: SolanaSimulator = bincode::deserialize(&simulator_buffer).expect("Failed to deserialize simulator");
        let mut binding = request.transactions.first().unwrap().clone();
        binding.message.set_recent_blockhash(Hash::default());
        request.transactions.pop();
        request.transactions.push(binding);
        let env = ExecutorEnv::builder()
            .write(&request)
            .unwrap()
            .write(&simulator)
            .unwrap()
            .build()
            .unwrap();
        let prover_opts = ProverOpts::fast();
        let prover = get_prover_server(&prover_opts).unwrap();
        let receipt = prover
            .prove(env, CUSTOM_METHOD_ELF)
            .unwrap()
            .receipt;
        let journal = receipt.journal.bytes.clone();
    }
}