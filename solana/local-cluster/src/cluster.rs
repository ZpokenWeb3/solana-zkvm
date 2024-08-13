use {
    solana_core::validator::{Validator, ValidatorConfig},
    solana_gossip::{cluster_info::Node, contact_info::ContactInfo},
    solana_ledger::shred::Shred,
    solana_quic_client::{QuicConfig, QuicConnectionManager, QuicPool},
    solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair},
    solana_streamer::socket::SocketAddrSpace,
    solana_tpu_client::tpu_client::TpuClient,
    std::{io::Result, path::PathBuf, sync::Arc},
};

pub type QuicTpuClient = TpuClient<QuicPool, QuicConnectionManager, QuicConfig>;

pub struct ValidatorInfo {
    pub keypair: Arc<Keypair>,
    pub voting_keypair: Arc<Keypair>,
    pub ledger_path: PathBuf,
    pub contact_info: ContactInfo,
}

pub struct ClusterValidatorInfo {
    pub info: ValidatorInfo,
    pub config: ValidatorConfig,
    pub validator: Option<Validator>,
}

impl ClusterValidatorInfo {
    pub fn new(
        validator_info: ValidatorInfo,
        config: ValidatorConfig,
        validator: Validator,
    ) -> Self {
        Self {
            info: validator_info,
            config,
            validator: Some(validator),
        }
    }
}

pub trait Cluster {
    fn get_node_pubkeys(&self) -> Vec<Pubkey>;
    fn get_validator_client(&self, pubkey: &Pubkey) -> Option<QuicTpuClient>;
    fn build_tpu_quic_client(&self) -> Result<QuicTpuClient>;
    fn build_tpu_quic_client_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> Result<QuicTpuClient>;
    fn get_contact_info(&self, pubkey: &Pubkey) -> Option<&ContactInfo>;
    fn exit_node(&mut self, pubkey: &Pubkey) -> ClusterValidatorInfo;
    fn restart_node(
        &mut self,
        pubkey: &Pubkey,
        cluster_validator_info: ClusterValidatorInfo,
        socket_addr_space: SocketAddrSpace,
    );
    fn create_restart_context(
        &mut self,
        pubkey: &Pubkey,
        cluster_validator_info: &mut ClusterValidatorInfo,
    ) -> (Node, Vec<ContactInfo>);
    fn restart_node_with_context(
        cluster_validator_info: ClusterValidatorInfo,
        restart_context: (Node, Vec<ContactInfo>),
        socket_addr_space: SocketAddrSpace,
    ) -> ClusterValidatorInfo;
    fn add_node(&mut self, pubkey: &Pubkey, cluster_validator_info: ClusterValidatorInfo);
    fn exit_restart_node(
        &mut self,
        pubkey: &Pubkey,
        config: ValidatorConfig,
        socket_addr_space: SocketAddrSpace,
    );
    fn set_entry_point(&mut self, entry_point_info: ContactInfo);
    fn send_shreds_to_validator(&self, dup_shreds: Vec<&Shred>, validator_key: &Pubkey);
}
