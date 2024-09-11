use serde::{Deserialize, Serialize};
use solana_simulator_types::result::SimulateSolanaRequest;
use crate::solana_simulator::SolanaSimulator;

pub mod bultins;
#[cfg(feature = "async_enabled")]
pub mod config_simulator;
#[cfg(feature = "async_enabled")]
pub mod rpc;
pub mod simulate_solana;
pub mod solana_simulator;


#[derive(Deserialize, Serialize)]
pub struct HostInput{
    pub simulator: SolanaSimulator,
    pub request: SimulateSolanaRequest
}
