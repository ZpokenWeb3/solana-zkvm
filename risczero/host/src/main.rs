mod utils;

use std::fs::{create_dir_all, File, OpenOptions};
use std::{fs, io};
use crate::utils::{encode_seal, parse_transactions_info, TEST_BLOCK_HASH};
use clap::{App, Arg};
use futures::future;
// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{CUSTOM_METHOD_ELF, CUSTOM_METHOD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use solana_sdk::hash::Hash;
use solana_sdk::transaction::VersionedTransaction;
use solana_simulator_types::result::SimulateSolanaRequest;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use serde::{Serialize};
use svm_core::rpc::Rpc;
use svm_core::{HostInput, rpc, simulate_solana};


const ENV_PATH: &str = "contracts/.env";

#[derive(Serialize)]
pub struct Groth16Output {
    pub(crate) journal: String,
    pub(crate) seal: String,
}

fn update_or_create_env(proof_path: &str, env_path: &str) -> io::Result<()> {
    if !Path::new(env_path).exists() {
        OpenOptions::new().create(true).write(true).open(env_path)?;
    }

    let file_content = fs::read_to_string(env_path)?;
    let mut lines: Vec<String> = file_content.lines().map(|line| line.to_string()).collect();
    let mut image_id_found = false;

    for line in lines.iter_mut() {
        if line.starts_with("LATEST_PROOF_PATH=") {
            *line = format!("LATEST_PROOF_PATH={}", proof_path);
            image_id_found = true;
            break;
        }
    }

    if !image_id_found {
        lines.push(format!("LATEST_PROOF_PATH={}", proof_path));
    }

    let mut file = OpenOptions::new().write(true).truncate(true).open(env_path)?;
    writeln!(file, "{}", lines.join("\n"))?;

    Ok(())
}

#[tokio::main]
async fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let options = App::new("simulate Solana")
        .arg(
            Arg::with_name("config_file")
                .long("config_file")
                .takes_value(true)
                .help("Path to the Solana CLI configuration file"),
        )
        .arg(
            Arg::with_name("commitment")
                .long("commitment")
                .takes_value(true)
                .help("Commitment level (e.g., 'confirmed', 'processed')"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .long("json_rpc_url")
                .takes_value(true)
                .help("URL of the Solana JSON RPC endpoint"),
        )
        .arg(
            Arg::with_name("keypair")
                .long("keypair")
                .takes_value(true)
                .help("Path to the keypair file"),
        )
        .arg(
            Arg::with_name("fee_payer")
                .long("fee_payer")
                .takes_value(true)
                .help("Path to the fee payer's keypair file"),
        )
        .arg(
            Arg::with_name("solana_key_for_config")
                .long("solana_key_for_config")
                .takes_value(true)
                .help("Public key for Solana config"),
        )
        .arg(
            Arg::with_name("transactions_file")
                .long("transactions_file")
                .takes_value(true)
                .help("Path to the Transactions file"),
        )
        .arg(
            Arg::with_name("block_hash")
                .long("block_hash")
                .takes_value(true)
                .help("Block hash"),
        )
        .get_matches();
    let config = &rpc::config::create(&options).unwrap();
    let rpc = rpc::config::build_rpc(config).await.unwrap();
    let transactions_info = parse_transactions_info(&options, config).unwrap();
    let futures: Vec<_> = transactions_info
        .iter()
        .map(|signature| rpc.get_transaction(signature))
        .collect();
    let results = future::join_all(futures).await;
    let transactions: Vec<VersionedTransaction> = results
        .into_iter()
        .filter_map(|result| {
            match result {
                Ok(Some(tx)) => Some(tx),
                _ => {
                    panic!("Transaction not found")
                }
            }
        })
        .collect();

    let block_hash = options.value_of("block_hash")
        .map_or_else(
            || Hash::from_str(TEST_BLOCK_HASH).unwrap(),
            |s| Hash::from_str(s).unwrap(),
        );

    let request = SimulateSolanaRequest {
        compute_units: None,
        heap_size: None,
        account_limit: None,
        verify: Some(true),
        blockhash: block_hash.to_bytes(),
        transactions,
        id: None,
    };

    let solana_simulator = simulate_solana::init_simulator(&rpc, request.clone())
        .await
        .unwrap();

    let input = HostInput {
        simulator: solana_simulator,
        request,
    };

    let input_slice = bincode::serialize(&input).unwrap();

    let env = ExecutorEnv::builder()
        .write_slice(&input_slice)
        .build()
        .unwrap();

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            CUSTOM_METHOD_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt;

    let journal = receipt.journal.bytes.clone();
    let seal_hex_string = format!("0x{}", hex::encode(encode_seal(&receipt).unwrap()));
    let journal_hex_string = format!("0x{}", hex::encode(journal));

    let output = Groth16Output{
        journal: journal_hex_string,
        seal: seal_hex_string,
    };

    let dir = "proofs";
    if !Path::new(dir).exists() {
        create_dir_all(dir).unwrap();
    }

    let file_path = format!("{}/{}_proof.json", dir, block_hash.to_string());

    let json_string = serde_json::to_string_pretty(&output).unwrap();
    let mut file = File::create(file_path.clone()).unwrap();
    file.write_all(json_string.as_bytes()).unwrap();

    println!("Output saved to: {:?}", file_path.clone());

    println!(
        "Encoded seal: {:?}",
        output.seal
    );
    println!("Journal: {:?}", output.journal);

    receipt.verify(CUSTOM_METHOD_ID).unwrap();

    update_or_create_env(&format!("../{}", file_path), ENV_PATH).unwrap();

}
