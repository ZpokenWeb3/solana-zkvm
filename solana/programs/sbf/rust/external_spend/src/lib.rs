//! Example Rust-based SBF program that moves a lamport from one account to another

#![allow(clippy::arithmetic_side_effects)]

extern crate solana_program;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

solana_program::entrypoint!(process_instruction);
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    // account 0 is the mint and not owned by this program, any debit of its lamports
    // should result in a failed program execution.  Test to ensure that this debit
    // is seen by the runtime and fails as expected
    **accounts[0].lamports.borrow_mut() -= 1;

    Ok(())
}
