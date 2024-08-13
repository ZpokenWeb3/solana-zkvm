use std::{env, str::FromStr};

use serde::{Deserialize, Serialize};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair};

#[derive(Debug)]
pub struct Config {
    pub evm_loader: Pubkey,
    pub key_for_config: Pubkey,
    pub fee_payer: Option<Keypair>,
    pub commitment: CommitmentConfig,
    pub solana_cli_config: solana_cli_config::Config,
    pub json_rpc_url: String,
    pub keypair_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct APIOptions {
    pub solana_cli_config_path: Option<String>,
    pub commitment: CommitmentConfig,
    pub solana_url: String,
    pub solana_timeout: u64,
    pub solana_max_retries: usize,
    pub evm_loader: Pubkey,
    pub key_for_config: Pubkey,
}

pub fn load_api_config_from_environment() -> APIOptions {
    let solana_cli_config_path: Option<String> =
        env::var("SOLANA_CLI_CONFIG_PATH").map(Some).unwrap_or(None);

    let commitment = env::var("COMMITMENT")
        .map(|v| v.to_lowercase())
        .ok()
        .and_then(|s| CommitmentConfig::from_str(&s).ok())
        .unwrap_or(CommitmentConfig::confirmed());

    let solana_url = env::var("SOLANA_URL").expect("solana url variable must be set");

    let solana_timeout = env::var("SOLANA_TIMEOUT").unwrap_or_else(|_| "30".to_string());
    let solana_timeout = solana_timeout
        .parse()
        .expect("SOLANA_TIMEOUT variable must be a valid number");

    let solana_max_retries = env::var("SOLANA_MAX_RETRIES").unwrap_or_else(|_| "10".to_string());
    let solana_max_retries = solana_max_retries
        .parse()
        .expect("SOLANA_MAX_RETRIES variable must be a valid number");

    let evm_loader = env::var("EVM_LOADER")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .expect("EVM_LOADER variable must be a valid pubkey");

    let key_for_config = env::var("SOLANA_KEY_FOR_CONFIG")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .expect("SOLANA_KEY_FOR_CONFIG variable must be a valid pubkey");

    APIOptions {
        solana_cli_config_path,
        commitment,
        solana_url,
        solana_timeout,
        solana_max_retries,
        evm_loader,
        key_for_config,
    }
}