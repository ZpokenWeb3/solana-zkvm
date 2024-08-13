use {
    super::*,
    spl_token_2022::{
        extension::memo_transfer::instruction::RequiredMemoTransfersInstruction,
        instruction::decode_instruction_type,
    },
};

pub(in crate::parse_token) fn parse_memo_transfer_instruction(
    instruction_data: &[u8],
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    check_num_token_accounts(account_indexes, 2)?;
    let instruction_type_str = match decode_instruction_type(instruction_data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?
    {
        RequiredMemoTransfersInstruction::Enable => "enable",
        RequiredMemoTransfersInstruction::Disable => "disable",
    };
    let mut value = json!({
        "account": account_keys[account_indexes[0] as usize].to_string(),
    });
    let map = value.as_object_mut().unwrap();
    parse_signers(
        map,
        1,
        account_keys,
        account_indexes,
        "owner",
        "multisigOwner",
    );
    Ok(ParsedInstructionEnum {
        instruction_type: format!("{instruction_type_str}RequiredMemoTransfers"),
        info: value,
    })
}

#[cfg(test)]
mod test {
    use {
        super::*,
        solana_sdk::pubkey::Pubkey,
        spl_token_2022::{
            extension::memo_transfer::instruction::{
                disable_required_transfer_memos, enable_required_transfer_memos,
            },
            solana_program::message::Message,
        },
    };

    #[test]
    fn test_parse_memo_transfer_instruction() {
        let account_pubkey = Pubkey::new_unique();

        // Enable, single owner
        let owner_pubkey = Pubkey::new_unique();
        let enable_memo_transfers_ix = enable_required_transfer_memos(
            &spl_token_2022::id(),
            &account_pubkey,
            &owner_pubkey,
            &[],
        )
        .unwrap();
        let message = Message::new(&[enable_memo_transfers_ix], None);
        let compiled_instruction = &message.instructions[0];
        assert_eq!(
            parse_token(
                compiled_instruction,
                &AccountKeys::new(&message.account_keys, None)
            )
            .unwrap(),
            ParsedInstructionEnum {
                instruction_type: "enableRequiredMemoTransfers".to_string(),
                info: json!({
                    "account": account_pubkey.to_string(),
                    "owner": owner_pubkey.to_string(),
                })
            }
        );

        // Enable, multisig owner
        let multisig_pubkey = Pubkey::new_unique();
        let multisig_signer0 = Pubkey::new_unique();
        let multisig_signer1 = Pubkey::new_unique();
        let enable_memo_transfers_ix = enable_required_transfer_memos(
            &spl_token_2022::id(),
            &account_pubkey,
            &multisig_pubkey,
            &[&multisig_signer0, &multisig_signer1],
        )
        .unwrap();
        let message = Message::new(&[enable_memo_transfers_ix], None);
        let compiled_instruction = &message.instructions[0];
        assert_eq!(
            parse_token(
                compiled_instruction,
                &AccountKeys::new(&message.account_keys, None)
            )
            .unwrap(),
            ParsedInstructionEnum {
                instruction_type: "enableRequiredMemoTransfers".to_string(),
                info: json!({
                    "account": account_pubkey.to_string(),
                    "multisigOwner": multisig_pubkey.to_string(),
                    "signers": vec![
                        multisig_signer0.to_string(),
                        multisig_signer1.to_string(),
                    ],
                })
            }
        );

        // Disable, single owner
        let enable_memo_transfers_ix = disable_required_transfer_memos(
            &spl_token_2022::id(),
            &account_pubkey,
            &owner_pubkey,
            &[],
        )
        .unwrap();
        let message = Message::new(&[enable_memo_transfers_ix], None);
        let compiled_instruction = &message.instructions[0];
        assert_eq!(
            parse_token(
                compiled_instruction,
                &AccountKeys::new(&message.account_keys, None)
            )
            .unwrap(),
            ParsedInstructionEnum {
                instruction_type: "disableRequiredMemoTransfers".to_string(),
                info: json!({
                    "account": account_pubkey.to_string(),
                    "owner": owner_pubkey.to_string(),
                })
            }
        );

        // Enable, multisig owner
        let multisig_pubkey = Pubkey::new_unique();
        let multisig_signer0 = Pubkey::new_unique();
        let multisig_signer1 = Pubkey::new_unique();
        let enable_memo_transfers_ix = disable_required_transfer_memos(
            &spl_token_2022::id(),
            &account_pubkey,
            &multisig_pubkey,
            &[&multisig_signer0, &multisig_signer1],
        )
        .unwrap();
        let message = Message::new(&[enable_memo_transfers_ix], None);
        let compiled_instruction = &message.instructions[0];
        assert_eq!(
            parse_token(
                compiled_instruction,
                &AccountKeys::new(&message.account_keys, None)
            )
            .unwrap(),
            ParsedInstructionEnum {
                instruction_type: "disableRequiredMemoTransfers".to_string(),
                info: json!({
                    "account": account_pubkey.to_string(),
                    "multisigOwner": multisig_pubkey.to_string(),
                    "signers": vec![
                        multisig_signer0.to_string(),
                        multisig_signer1.to_string(),
                    ],
                })
            }
        );
    }
}
