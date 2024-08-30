#![cfg_attr(RUSTC_WITH_SPECIALIZATION, feature(min_specialization))]
#![allow(clippy::arithmetic_side_effects)]

pub mod account_loader;
pub mod account_overrides;
pub mod account_rent_state;
pub mod message_processor;
pub mod nonce_info;
pub mod program_loader;
pub mod rollback_accounts;
pub mod runtime_config;
pub mod transaction_account_state_info;
pub mod transaction_error_metrics;
pub mod transaction_processing_callback;
pub mod transaction_processor;
pub mod transaction_results;

#[macro_use]
#[cfg(feature = "metrics")]
extern crate solana_metrics;

#[cfg_attr(feature = "frozen-abi", macro_use)]
#[cfg(feature = "frozen-abi")]
extern crate solana_frozen_abi_macro;
