use anyhow::bail;
use clap::ArgMatches;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::InnerReceipt;
use solana_sdk::signature::Signature;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use svm_core::rpc::config::Config;

const MAIN_NET_URL: &str = "https://api.mainnet-beta.solana.com";
const TEST_SIGNATURE: &str = "5Q5ZCHZu2zJhngwpJXYucJpDvhGbYjLYncLV3KZt2R75jwPSZqFKmxq9K3WyDYqtMLugrVPXWieMvQgEq6XmzkL7";
pub(crate) const TEST_BLOCK_HASH: &str = "HuKexVov6nz7F4veDEanw4FNYbFzyA67U6Phhrvbi4v2";

pub fn encode_seal(receipt: &risc0_zkvm::Receipt) -> anyhow::Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0u8; 4];
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    anyhow::Ok(seal)
}

pub fn is_main_net(json_rpc_url: &str) -> bool {
    json_rpc_url == MAIN_NET_URL
}

pub fn parse_transactions_info(options: &ArgMatches, config: &Config)
                               -> Result<Vec<Signature>, Box<dyn std::error::Error>> {
    options
        .value_of("transactions_file")
        .map_or_else(
            || {
                assert!(is_main_net(&config.json_rpc_url) && options.value_of("block_hash").is_none());
                Ok(
                    vec![
                        Signature::from_str(
                            TEST_SIGNATURE
                        )
                            .unwrap()
                    ]
                )
            }, |file_path| {
                let mut file = File::open(file_path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let json_content: Vec<String> = serde_json::from_str(&contents)?;
                let signatures: Vec<Signature> = json_content.iter().map(|content| Signature::from_str(&content).unwrap()).collect();
                Ok(signatures)
            },
        )
}