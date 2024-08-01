//! @brief Example Rust-based BPF program that exercises the sol_remaining_compute_units syscall

extern crate solana_program;
use solana_program::{
    account_info::AccountInfo, compute_units::sol_remaining_compute_units,
    entrypoint::ProgramResult, msg, pubkey::Pubkey,
};
solana_program::entrypoint!(process_instruction);
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let mut i = 0u32;
    for _ in 0..100_000 {
        if i % 500 == 0 {
            let remaining = sol_remaining_compute_units();
            msg!("remaining compute units: {:?}", remaining);
            if remaining < 25_000 {
                break;
            }
        }
        i = i.saturating_add(1);
    }

    msg!("i: {:?}", i);

    Ok(())
}
