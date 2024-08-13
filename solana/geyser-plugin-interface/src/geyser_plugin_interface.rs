/// The interface for Geyser plugins. A plugin must implement
/// the GeyserPlugin trait to work with the runtime.
/// In addition, the dynamic library must export a "C" function _create_plugin which
/// creates the implementation of the plugin.
use {
    solana_sdk::{
        clock::{Slot, UnixTimestamp},
        signature::Signature,
        transaction::SanitizedTransaction,
    },
    solana_transaction_status::{Reward, TransactionStatusMeta},
    std::{any::Any, error, io},
    thiserror::Error,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
/// Information about an account being updated
pub struct ReplicaAccountInfo<'a> {
    /// The Pubkey for the account
    pub pubkey: &'a [u8],

    /// The lamports for the account
    pub lamports: u64,

    /// The Pubkey of the owner program account
    pub owner: &'a [u8],

    /// This account's data contains a loaded program (and is now read-only)
    pub executable: bool,

    /// The epoch at which this account will next owe rent
    pub rent_epoch: u64,

    /// The data held in this account.
    pub data: &'a [u8],

    /// A global monotonically increasing atomic number, which can be used
    /// to tell the order of the account update. For example, when an
    /// account is updated in the same slot multiple times, the update
    /// with higher write_version should supersede the one with lower
    /// write_version.
    pub write_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
/// Information about an account being updated
/// (extended with transaction signature doing this update)
pub struct ReplicaAccountInfoV2<'a> {
    /// The Pubkey for the account
    pub pubkey: &'a [u8],

    /// The lamports for the account
    pub lamports: u64,

    /// The Pubkey of the owner program account
    pub owner: &'a [u8],

    /// This account's data contains a loaded program (and is now read-only)
    pub executable: bool,

    /// The epoch at which this account will next owe rent
    pub rent_epoch: u64,

    /// The data held in this account.
    pub data: &'a [u8],

    /// A global monotonically increasing atomic number, which can be used
    /// to tell the order of the account update. For example, when an
    /// account is updated in the same slot multiple times, the update
    /// with higher write_version should supersede the one with lower
    /// write_version.
    pub write_version: u64,

    /// First signature of the transaction caused this account modification
    pub txn_signature: Option<&'a Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
/// Information about an account being updated
/// (extended with reference to transaction doing this update)
pub struct ReplicaAccountInfoV3<'a> {
    /// The Pubkey for the account
    pub pubkey: &'a [u8],

    /// The lamports for the account
    pub lamports: u64,

    /// The Pubkey of the owner program account
    pub owner: &'a [u8],

    /// This account's data contains a loaded program (and is now read-only)
    pub executable: bool,

    /// The epoch at which this account will next owe rent
    pub rent_epoch: u64,

    /// The data held in this account.
    pub data: &'a [u8],

    /// A global monotonically increasing atomic number, which can be used
    /// to tell the order of the account update. For example, when an
    /// account is updated in the same slot multiple times, the update
    /// with higher write_version should supersede the one with lower
    /// write_version.
    pub write_version: u64,

    /// Reference to transaction causing this account modification
    pub txn: Option<&'a SanitizedTransaction>,
}

/// A wrapper to future-proof ReplicaAccountInfo handling.
/// If there were a change to the structure of ReplicaAccountInfo,
/// there would be new enum entry for the newer version, forcing
/// plugin implementations to handle the change.
#[repr(u32)]
pub enum ReplicaAccountInfoVersions<'a> {
    V0_0_1(&'a ReplicaAccountInfo<'a>),
    V0_0_2(&'a ReplicaAccountInfoV2<'a>),
    V0_0_3(&'a ReplicaAccountInfoV3<'a>),
}

/// Information about a transaction
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaTransactionInfo<'a> {
    /// The first signature of the transaction, used for identifying the transaction.
    pub signature: &'a Signature,

    /// Indicates if the transaction is a simple vote transaction.
    pub is_vote: bool,

    /// The sanitized transaction.
    pub transaction: &'a SanitizedTransaction,

    /// Metadata of the transaction status.
    pub transaction_status_meta: &'a TransactionStatusMeta,
}

/// Information about a transaction, including index in block
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaTransactionInfoV2<'a> {
    /// The first signature of the transaction, used for identifying the transaction.
    pub signature: &'a Signature,

    /// Indicates if the transaction is a simple vote transaction.
    pub is_vote: bool,

    /// The sanitized transaction.
    pub transaction: &'a SanitizedTransaction,

    /// Metadata of the transaction status.
    pub transaction_status_meta: &'a TransactionStatusMeta,

    /// The transaction's index in the block
    pub index: usize,
}

/// A wrapper to future-proof ReplicaTransactionInfo handling.
/// If there were a change to the structure of ReplicaTransactionInfo,
/// there would be new enum entry for the newer version, forcing
/// plugin implementations to handle the change.
#[repr(u32)]
pub enum ReplicaTransactionInfoVersions<'a> {
    V0_0_1(&'a ReplicaTransactionInfo<'a>),
    V0_0_2(&'a ReplicaTransactionInfoV2<'a>),
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaEntryInfo<'a> {
    /// The slot number of the block containing this Entry
    pub slot: Slot,
    /// The Entry's index in the block
    pub index: usize,
    /// The number of hashes since the previous Entry
    pub num_hashes: u64,
    /// The Entry's SHA-256 hash, generated from the previous Entry's hash with
    /// `solana_entry::entry::next_hash()`
    pub hash: &'a [u8],
    /// The number of executed transactions in the Entry
    pub executed_transaction_count: u64,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaEntryInfoV2<'a> {
    /// The slot number of the block containing this Entry
    pub slot: Slot,
    /// The Entry's index in the block
    pub index: usize,
    /// The number of hashes since the previous Entry
    pub num_hashes: u64,
    /// The Entry's SHA-256 hash, generated from the previous Entry's hash with
    /// `solana_entry::entry::next_hash()`
    pub hash: &'a [u8],
    /// The number of executed transactions in the Entry
    pub executed_transaction_count: u64,
    /// The index-in-block of the first executed transaction in this Entry
    pub starting_transaction_index: usize,
}

/// A wrapper to future-proof ReplicaEntryInfo handling. To make a change to the structure of
/// ReplicaEntryInfo, add an new enum variant wrapping a newer version, which will force plugin
/// implementations to handle the change.
#[repr(u32)]
pub enum ReplicaEntryInfoVersions<'a> {
    V0_0_1(&'a ReplicaEntryInfo<'a>),
    V0_0_2(&'a ReplicaEntryInfoV2<'a>),
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaBlockInfo<'a> {
    pub slot: Slot,
    pub blockhash: &'a str,
    pub rewards: &'a [Reward],
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
}

/// Extending ReplicaBlockInfo by sending the executed_transaction_count.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaBlockInfoV2<'a> {
    pub parent_slot: Slot,
    pub parent_blockhash: &'a str,
    pub slot: Slot,
    pub blockhash: &'a str,
    pub rewards: &'a [Reward],
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
    pub executed_transaction_count: u64,
}

/// Extending ReplicaBlockInfo by sending the entries_count.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReplicaBlockInfoV3<'a> {
    pub parent_slot: Slot,
    pub parent_blockhash: &'a str,
    pub slot: Slot,
    pub blockhash: &'a str,
    pub rewards: &'a [Reward],
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
    pub executed_transaction_count: u64,
    pub entry_count: u64,
}

#[repr(u32)]
pub enum ReplicaBlockInfoVersions<'a> {
    V0_0_1(&'a ReplicaBlockInfo<'a>),
    V0_0_2(&'a ReplicaBlockInfoV2<'a>),
    V0_0_3(&'a ReplicaBlockInfoV3<'a>),
}

/// Errors returned by plugin calls
#[derive(Error, Debug)]
#[repr(u32)]
pub enum GeyserPluginError {
    /// Error opening the configuration file; for example, when the file
    /// is not found or when the validator process has no permission to read it.
    #[error("Error opening config file. Error detail: ({0}).")]
    ConfigFileOpenError(#[from] io::Error),

    /// Error in reading the content of the config file or the content
    /// is not in the expected format.
    #[error("Error reading config file. Error message: ({msg})")]
    ConfigFileReadError { msg: String },

    /// Error when updating the account.
    #[error("Error updating account. Error message: ({msg})")]
    AccountsUpdateError { msg: String },

    /// Error when updating the slot status
    #[error("Error updating slot status. Error message: ({msg})")]
    SlotStatusUpdateError { msg: String },

    /// Any custom error defined by the plugin.
    #[error("Plugin-defined custom error. Error message: ({0})")]
    Custom(Box<dyn error::Error + Send + Sync>),

    /// Error when updating the transaction.
    #[error("Error updating transaction. Error message: ({msg})")]
    TransactionUpdateError { msg: String },
}

/// The current status of a slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SlotStatus {
    /// The highest slot of the heaviest fork processed by the node. Ledger state at this slot is
    /// not derived from a confirmed or finalized block, but if multiple forks are present, is from
    /// the fork the validator believes is most likely to finalize.
    Processed,

    /// The highest slot having reached max vote lockout.
    Rooted,

    /// The highest slot that has been voted on by supermajority of the cluster, ie. is confirmed.
    Confirmed,
}

impl SlotStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SlotStatus::Confirmed => "confirmed",
            SlotStatus::Processed => "processed",
            SlotStatus::Rooted => "rooted",
        }
    }
}

pub type Result<T> = std::result::Result<T, GeyserPluginError>;

/// Defines a Geyser plugin, to stream data from the runtime.
/// Geyser plugins must describe desired behavior for load and unload,
/// as well as how they will handle streamed data.
pub trait GeyserPlugin: Any + Send + Sync + std::fmt::Debug {
    /// The callback to allow the plugin to setup the logging configuration using the logger
    /// and log level specified by the validator. Will be called first on load/reload, before any other
    /// callback, and only called once.
    /// # Examples
    ///
    /// ```
    /// use agave_geyser_plugin_interface::geyser_plugin_interface::{GeyserPlugin,
    /// GeyserPluginError, Result};
    ///
    /// #[derive(Debug)]
    /// struct SamplePlugin;
    /// impl GeyserPlugin for SamplePlugin {
    ///     fn setup_logger(&self, logger: &'static dyn log::Log, level: log::LevelFilter) -> Result<()> {
    ///        log::set_max_level(level);
    ///        if let Err(err) = log::set_logger(logger) {
    ///            return Err(GeyserPluginError::Custom(Box::new(err)));
    ///        }
    ///        Ok(())
    ///     }
    ///     fn name(&self) -> &'static str {
    ///         &"sample"
    ///     }
    /// }
    /// ```
    #[allow(unused_variables)]
    fn setup_logger(&self, logger: &'static dyn log::Log, level: log::LevelFilter) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str;

    /// The callback called when a plugin is loaded by the system,
    /// used for doing whatever initialization is required by the plugin.
    /// The _config_file contains the name of the
    /// of the config file. The config must be in JSON format and
    /// include a field "libpath" indicating the full path
    /// name of the shared library implementing this interface.
    fn on_load(&mut self, _config_file: &str, _is_reload: bool) -> Result<()> {
        Ok(())
    }

    /// The callback called right before a plugin is unloaded by the system
    /// Used for doing cleanup before unload.
    fn on_unload(&mut self) {}

    /// Called when an account is updated at a slot.
    /// When `is_startup` is true, it indicates the account is loaded from
    /// snapshots when the validator starts up. When `is_startup` is false,
    /// the account is updated during transaction processing.
    #[allow(unused_variables)]
    fn update_account(
        &self,
        account: ReplicaAccountInfoVersions,
        slot: Slot,
        is_startup: bool,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when all accounts are notified of during startup.
    fn notify_end_of_startup(&self) -> Result<()> {
        Ok(())
    }

    /// Called when a slot status is updated
    #[allow(unused_variables)]
    fn update_slot_status(
        &self,
        slot: Slot,
        parent: Option<u64>,
        status: SlotStatus,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a transaction is processed in a slot.
    #[allow(unused_variables)]
    fn notify_transaction(
        &self,
        transaction: ReplicaTransactionInfoVersions,
        slot: Slot,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when an entry is executed.
    #[allow(unused_variables)]
    fn notify_entry(&self, entry: ReplicaEntryInfoVersions) -> Result<()> {
        Ok(())
    }

    /// Called when block's metadata is updated.
    #[allow(unused_variables)]
    fn notify_block_metadata(&self, blockinfo: ReplicaBlockInfoVersions) -> Result<()> {
        Ok(())
    }

    /// Check if the plugin is interested in account data
    /// Default is true -- if the plugin is not interested in
    /// account data, please return false.
    fn account_data_notifications_enabled(&self) -> bool {
        true
    }

    /// Check if the plugin is interested in transaction data
    /// Default is false -- if the plugin is interested in
    /// transaction data, please return true.
    fn transaction_notifications_enabled(&self) -> bool {
        false
    }

    /// Check if the plugin is interested in entry data
    /// Default is false -- if the plugin is interested in
    /// entry data, return true.
    fn entry_notifications_enabled(&self) -> bool {
        false
    }
}
