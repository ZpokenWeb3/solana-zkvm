use clap::ArgMatches;
use solana_clap_utils::{
    input_parsers::pubkey_of, input_validators::normalize_to_url_if_moniker,
    keypair::keypair_from_path,
};
use solana_sdk::{commitment_config::CommitmentConfig, signature::Keypair};
use std::{env, str::FromStr};
use serde::{Deserialize, Serialize};
use solana_sdk::signer::Signer;
use solana_simulator_types::error::NeonError;
use solana_sdk::pubkey::Pubkey;
use crate::rpc::{CloneRpcClient, RpcEnum};

#[derive(Debug)]
pub struct Config {
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
    pub key_for_config: Pubkey,
}

/// # Errors
#[must_use]
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
        key_for_config,
    }
}


/// # Panics
/// # Errors
/// `EvmLoaderNotSpecified` - if `evm_loader` is not specified
/// `KeypairNotSpecified` - if `signer` is not specified
pub fn create(options: &ArgMatches) -> Result<Config, NeonError> {
    let solana_cli_config = options
        .value_of("config_file")
        .map_or_else(solana_cli_config::Config::default, |config_file| {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        });

    let commitment =
        CommitmentConfig::from_str(options.value_of("commitment").unwrap_or("confirmed")).unwrap();

    let json_rpc_url = normalize_to_url_if_moniker(
        options
            .value_of("json_rpc_url")
            .unwrap_or(&solana_cli_config.json_rpc_url),
    );

    let keypair_path: String = options
        .value_of("keypair")
        .unwrap_or(&solana_cli_config.keypair_path)
        .to_owned();

    let fee_payer = keypair_from_path(
        options,
        options
            .value_of("fee_payer")
            .unwrap_or(&solana_cli_config.keypair_path),
        "fee_payer",
        true,
    )
        .ok();

    let key_for_config = if let Some(key_for_config) = pubkey_of(options, "solana_key_for_config") {
        key_for_config
    } else {
        fee_payer
            .as_ref()
            .map(Keypair::pubkey)
            .ok_or(NeonError::SolanaKeyForConfigNotSpecified)?
    };


    Ok(Config {
        key_for_config,
        fee_payer,
        commitment,
        solana_cli_config,
        json_rpc_url,
        keypair_path,
    })
}

pub async fn build_rpc(config: &Config) -> Result<RpcEnum, NeonError> {
    Ok(RpcEnum::CloneRpcClient(CloneRpcClient::new_from_config(config)))
}
