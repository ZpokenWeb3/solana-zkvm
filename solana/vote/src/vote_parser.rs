use {
    crate::vote_transaction::VoteTransaction,
    solana_sdk::{
        hash::Hash,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        signature::Signature,
        transaction::{SanitizedTransaction, Transaction},
        vote::instruction::VoteInstruction,
    },
};

pub type ParsedVote = (Pubkey, VoteTransaction, Option<Hash>, Signature);

// Used for locally forwarding processed vote transactions to consensus
pub fn parse_sanitized_vote_transaction(tx: &SanitizedTransaction) -> Option<ParsedVote> {
    // Check first instruction for a vote
    let message = tx.message();
    let (program_id, first_instruction) = message.program_instructions_iter().next()?;
    if !solana_sdk::vote::program::check_id(program_id) {
        return None;
    }
    let first_account = usize::from(*first_instruction.accounts.first()?);
    let key = message.account_keys().get(first_account)?;
    let (vote, switch_proof_hash) = parse_vote_instruction_data(&first_instruction.data)?;
    let signature = tx.signatures().first().cloned().unwrap_or_default();
    Some((*key, vote, switch_proof_hash, signature))
}

// Used for parsing gossip vote transactions
pub fn parse_vote_transaction(tx: &Transaction) -> Option<ParsedVote> {
    // Check first instruction for a vote
    let message = tx.message();
    let first_instruction = message.instructions.first()?;
    let program_id_index = usize::from(first_instruction.program_id_index);
    let program_id = message.account_keys.get(program_id_index)?;
    if !solana_sdk::vote::program::check_id(program_id) {
        return None;
    }
    let first_account = usize::from(*first_instruction.accounts.first()?);
    let key = message.account_keys.get(first_account)?;
    let (vote, switch_proof_hash) = parse_vote_instruction_data(&first_instruction.data)?;
    let signature = tx.signatures.first().cloned().unwrap_or_default();
    Some((*key, vote, switch_proof_hash, signature))
}

fn parse_vote_instruction_data(
    vote_instruction_data: &[u8],
) -> Option<(VoteTransaction, Option<Hash>)> {
    match limited_deserialize(vote_instruction_data).ok()? {
        VoteInstruction::Vote(vote) => Some((VoteTransaction::from(vote), None)),
        VoteInstruction::VoteSwitch(vote, hash) => Some((VoteTransaction::from(vote), Some(hash))),
        VoteInstruction::UpdateVoteState(vote_state_update) => {
            Some((VoteTransaction::from(vote_state_update), None))
        }
        VoteInstruction::UpdateVoteStateSwitch(vote_state_update, hash) => {
            Some((VoteTransaction::from(vote_state_update), Some(hash)))
        }
        VoteInstruction::CompactUpdateVoteState(vote_state_update) => {
            Some((VoteTransaction::from(vote_state_update), None))
        }
        VoteInstruction::CompactUpdateVoteStateSwitch(vote_state_update, hash) => {
            Some((VoteTransaction::from(vote_state_update), Some(hash)))
        }
        VoteInstruction::TowerSync(tower_sync) => Some((VoteTransaction::from(tower_sync), None)),
        VoteInstruction::TowerSyncSwitch(tower_sync, hash) => {
            Some((VoteTransaction::from(tower_sync), Some(hash)))
        }
        VoteInstruction::Authorize(_, _)
        | VoteInstruction::AuthorizeChecked(_)
        | VoteInstruction::AuthorizeWithSeed(_)
        | VoteInstruction::AuthorizeCheckedWithSeed(_)
        | VoteInstruction::InitializeAccount(_)
        | VoteInstruction::UpdateCommission(_)
        | VoteInstruction::UpdateValidatorIdentity
        | VoteInstruction::Withdraw(_) => None,
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        solana_sdk::{
            clock::Slot,
            hash::hash,
            signature::{Keypair, Signer},
            vote::{instruction as vote_instruction, state::Vote},
        },
    };

    // Reimplemented locally from Vote program.
    fn new_vote_transaction(
        slots: Vec<Slot>,
        bank_hash: Hash,
        blockhash: Hash,
        node_keypair: &Keypair,
        vote_keypair: &Keypair,
        authorized_voter_keypair: &Keypair,
        switch_proof_hash: Option<Hash>,
    ) -> Transaction {
        let votes = Vote::new(slots, bank_hash);
        let vote_ix = if let Some(switch_proof_hash) = switch_proof_hash {
            vote_instruction::vote_switch(
                &vote_keypair.pubkey(),
                &authorized_voter_keypair.pubkey(),
                votes,
                switch_proof_hash,
            )
        } else {
            vote_instruction::vote(
                &vote_keypair.pubkey(),
                &authorized_voter_keypair.pubkey(),
                votes,
            )
        };

        let mut vote_tx = Transaction::new_with_payer(&[vote_ix], Some(&node_keypair.pubkey()));

        vote_tx.partial_sign(&[node_keypair], blockhash);
        vote_tx.partial_sign(&[authorized_voter_keypair], blockhash);
        vote_tx
    }

    fn run_test_parse_vote_transaction(input_hash: Option<Hash>) {
        let node_keypair = Keypair::new();
        let vote_keypair = Keypair::new();
        let auth_voter_keypair = Keypair::new();
        let bank_hash = Hash::default();
        let vote_tx = new_vote_transaction(
            vec![42],
            bank_hash,
            Hash::default(),
            &node_keypair,
            &vote_keypair,
            &auth_voter_keypair,
            input_hash,
        );
        let (key, vote, hash, signature) = parse_vote_transaction(&vote_tx).unwrap();
        assert_eq!(hash, input_hash);
        assert_eq!(vote, VoteTransaction::from(Vote::new(vec![42], bank_hash)));
        assert_eq!(key, vote_keypair.pubkey());
        assert_eq!(signature, vote_tx.signatures[0]);

        // Test bad program id fails
        let mut vote_ix = vote_instruction::vote(
            &vote_keypair.pubkey(),
            &auth_voter_keypair.pubkey(),
            Vote::new(vec![1, 2], Hash::default()),
        );
        vote_ix.program_id = Pubkey::default();
        let vote_tx = Transaction::new_with_payer(&[vote_ix], Some(&node_keypair.pubkey()));
        assert!(parse_vote_transaction(&vote_tx).is_none());
    }

    #[test]
    fn test_parse_vote_transaction() {
        run_test_parse_vote_transaction(None);
        run_test_parse_vote_transaction(Some(hash(&[42u8])));
    }
}
