use async_trait::async_trait;
use enum_dispatch::enum_dispatch;


use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;
use solana_simulator_types::result::NeonResult;

use crate::rpc::CloneRpcClient;
use crate::solana_simulator::SolanaSimulator;
use crate::rpc::RpcEnum;


#[allow(clippy::large_enum_variant)]
pub enum ConfigSimulator<'r> {
    CloneRpcClient {
        program_id: Pubkey,
        rpc: &'r CloneRpcClient,
    },
    ProgramTestContext {
        program_id: Pubkey,
        simulator: SolanaSimulator,
    },
}

#[async_trait(?Send)]
#[enum_dispatch]
pub trait BuildConfigSimulator {
    fn use_cache(&self) -> bool;
    async fn build_config_simulator(&self, program_id: Pubkey) -> NeonResult<ConfigSimulator>;
}

#[async_trait(?Send)]
impl BuildConfigSimulator for CloneRpcClient {
    fn use_cache(&self) -> bool {
        true
    }

    async fn build_config_simulator(&self, program_id: Pubkey) -> NeonResult<ConfigSimulator> {
        Ok(ConfigSimulator::CloneRpcClient {
            program_id,
            rpc: self,
        })
    }
}
