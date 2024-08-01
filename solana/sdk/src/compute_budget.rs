//! The compute budget native program.

#![cfg(feature = "full")]

#[cfg(feature = "borsh")]
use {
    crate::instruction::Instruction,
    borsh::{BorshDeserialize, BorshSerialize},
};

crate::declare_id!("ComputeBudget111111111111111111111111111111");

/// Compute Budget Instructions
#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ComputeBudgetInstruction {
    Unused, // deprecated variant, reserved value.
    /// Request a specific transaction-wide program heap region size in bytes.
    /// The value requested must be a multiple of 1024. This new heap region
    /// size applies to each program executed in the transaction, including all
    /// calls to CPIs.
    RequestHeapFrame(u32),
    /// Set a specific compute unit limit that the transaction is allowed to consume.
    SetComputeUnitLimit(u32),
    /// Set a compute unit price in "micro-lamports" to pay a higher transaction
    /// fee for higher transaction prioritization.
    SetComputeUnitPrice(u64),
    /// Set a specific transaction-wide account data size limit, in bytes, is allowed to load.
    SetLoadedAccountsDataSizeLimit(u32),
}

impl ComputeBudgetInstruction {
    #[cfg(feature = "borsh")]
    /// Create a `ComputeBudgetInstruction::RequestHeapFrame` `Instruction`
    pub fn request_heap_frame(bytes: u32) -> Instruction {
        Instruction::new_with_borsh(id(), &Self::RequestHeapFrame(bytes), vec![])
    }

    #[cfg(feature = "borsh")]
    /// Create a `ComputeBudgetInstruction::SetComputeUnitLimit` `Instruction`
    pub fn set_compute_unit_limit(units: u32) -> Instruction {
        Instruction::new_with_borsh(id(), &Self::SetComputeUnitLimit(units), vec![])
    }

    #[cfg(feature = "borsh")]
    /// Create a `ComputeBudgetInstruction::SetComputeUnitPrice` `Instruction`
    pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
        Instruction::new_with_borsh(id(), &Self::SetComputeUnitPrice(micro_lamports), vec![])
    }

    /// Serialize Instruction using borsh, this is only used in runtime::cost_model::tests but compilation
    /// can't be restricted as it's used across packages
    #[cfg(all(feature = "dev-context-only-utils", feature = "borsh"))]
    pub fn pack(self) -> Result<Vec<u8>, borsh::io::Error> {
        borsh::to_vec(&self)
    }

    #[cfg(feature = "borsh")]
    /// Create a `ComputeBudgetInstruction::SetLoadedAccountsDataSizeLimit` `Instruction`
    pub fn set_loaded_accounts_data_size_limit(bytes: u32) -> Instruction {
        Instruction::new_with_borsh(id(), &Self::SetLoadedAccountsDataSizeLimit(bytes), vec![])
    }
}
