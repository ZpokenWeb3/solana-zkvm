use solana_program::{
    account_info::{AccountInfo, next_account_info}, 
    entrypoint, 
    entrypoint::ProgramResult, 
    msg, 
    pubkey::Pubkey, 
    program_error::ProgramError, 
    sysvar::{Sysvar, clock::Clock},
    system_instruction,
};

use borsh::{BorshDeserialize, BorshSerialize};

entrypoint!(process_instruction);

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct GameData {
    pub is_initialized: bool,
    pub bet_amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum CustomError {
    InsufficientFundsForTransaction,
}

impl From<CustomError> for ProgramError {
    fn from(e: CustomError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

fn transfer_service_fee_lamports(
    from_account: &AccountInfo,
    to_account: &AccountInfo,
    amount_of_lamports: u64,
) -> ProgramResult {
    // Does the from account have enough lamports to transfer?
    if **from_account.try_borrow_lamports()? < amount_of_lamports {
        return Err(CustomError::InsufficientFundsForTransaction.into());
    }
    // Debit from_account and credit to_account
    **from_account.try_borrow_mut_lamports()? -= amount_of_lamports;
    **to_account.try_borrow_mut_lamports()? += amount_of_lamports;
    Ok(())
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let game_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;

    let game_data = GameData::try_from_slice(&instruction_data)?;

    if !game_data.is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }

    let clock = Clock::get()?;
    let game_result = (clock.unix_timestamp as u64) % 2;

    let bet_amount_float = game_data.bet_amount as f64; // Convert to f64
    let result = bet_amount_float * 0.95; // Now you can do the multiplication
    let winnings = result.round() as u64;  

    // // Create a `transfer`
    if game_result == 0 {
        transfer_service_fee_lamports(game_account, user_account, winnings)?;
        msg!("Heads! You've won!");
    } else {
        transfer_service_fee_lamports(user_account, game_account, game_data.bet_amount)?;
        msg!("Tails! You've lost!");
    }

    Ok(())
}