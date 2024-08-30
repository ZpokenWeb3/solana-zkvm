//! The 256-bit batched range proof instruction.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        range_proof::RangeProof,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::batched_range_proof::{MAX_COMMITMENTS, MAX_SINGLE_BIT_LENGTH},
        },
    },
    std::convert::TryInto,
};
use {
    crate::{
        range_proof::pod::PodRangeProofU256,
        zk_elgamal_proof_program::proof_data::{
            batched_range_proof::BatchedRangeProofContext, ProofType, ZkProofData,
        },
    },
    bytemuck_derive::{Pod, Zeroable},
};

#[cfg(not(target_os = "solana"))]
const BATCHED_RANGE_PROOF_U256_BIT_LENGTH: usize = 256;

/// The instruction data that is needed for the
/// `ProofInstruction::BatchedRangeProofU256Data` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofU256Data {
    /// The context data for a batched range proof
    pub context: BatchedRangeProofContext,

    /// The batched range proof
    pub proof: PodRangeProofU256,
}

#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofU256Data {
    pub fn new(
        commitments: Vec<&PedersenCommitment>,
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        openings: Vec<&PedersenOpening>,
    ) -> Result<Self, ProofGenerationError> {
        // Range proof on 256 bit length could potentially result in an unexpected behavior and
        // therefore, restrict the bit length to be at most 128. This check is not needed for the
        // `BatchedRangeProofU64` or `BatchedRangeProofU128`.
        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofGenerationError::IllegalCommitmentLength);
        }

        // the sum of the bit lengths must be 256
        let batched_bit_length = bit_lengths
            .iter()
            .try_fold(0_usize, |acc, &x| acc.checked_add(x))
            .ok_or(ProofGenerationError::IllegalAmountBitLength)?;
        if batched_bit_length != BATCHED_RANGE_PROOF_U256_BIT_LENGTH {
            return Err(ProofGenerationError::IllegalAmountBitLength);
        }

        let context =
            BatchedRangeProofContext::new(&commitments, &amounts, &bit_lengths, &openings)?;

        let mut transcript = context.new_transcript();
        let proof = RangeProof::new(amounts, bit_lengths, openings, &mut transcript)?
            .try_into()
            .map_err(|_| ProofGenerationError::ProofLength)?;

        Ok(Self { context, proof })
    }
}

impl ZkProofData<BatchedRangeProofContext> for BatchedRangeProofU256Data {
    const PROOF_TYPE: ProofType = ProofType::BatchedRangeProofU256;

    fn context_data(&self) -> &BatchedRangeProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let (commitments, bit_lengths) = self.context.try_into()?;
        let num_commitments = commitments.len();

        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        if num_commitments > MAX_COMMITMENTS || num_commitments != bit_lengths.len() {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        let mut transcript = self.context_data().new_transcript();
        let proof: RangeProof = self.proof.try_into()?;

        proof
            .verify(commitments.iter().collect(), bit_lengths, &mut transcript)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            encryption::pedersen::Pedersen, range_proof::errors::RangeProofVerificationError,
            zk_elgamal_proof_program::errors::ProofVerificationError,
        },
    };

    #[test]
    fn test_batched_range_proof_256_instruction_correctness() {
        let amount_1 = 4294967295_u64;
        let amount_2 = 77_u64;
        let amount_3 = 99_u64;
        let amount_4 = 99_u64;
        let amount_5 = 11_u64;
        let amount_6 = 33_u64;
        let amount_7 = 99_u64;
        let amount_8 = 99_u64;

        let (commitment_1, opening_1) = Pedersen::new(amount_1);
        let (commitment_2, opening_2) = Pedersen::new(amount_2);
        let (commitment_3, opening_3) = Pedersen::new(amount_3);
        let (commitment_4, opening_4) = Pedersen::new(amount_4);
        let (commitment_5, opening_5) = Pedersen::new(amount_5);
        let (commitment_6, opening_6) = Pedersen::new(amount_6);
        let (commitment_7, opening_7) = Pedersen::new(amount_7);
        let (commitment_8, opening_8) = Pedersen::new(amount_8);

        let proof_data = BatchedRangeProofU256Data::new(
            vec![
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            vec![
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            vec![32, 32, 32, 32, 32, 32, 32, 32],
            vec![
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount_1 = 4294967296_u64; // not representable as a 32-bit number
        let amount_2 = 77_u64;
        let amount_3 = 99_u64;
        let amount_4 = 99_u64;
        let amount_5 = 11_u64;
        let amount_6 = 33_u64;
        let amount_7 = 99_u64;
        let amount_8 = 99_u64;

        let (commitment_1, opening_1) = Pedersen::new(amount_1);
        let (commitment_2, opening_2) = Pedersen::new(amount_2);
        let (commitment_3, opening_3) = Pedersen::new(amount_3);
        let (commitment_4, opening_4) = Pedersen::new(amount_4);
        let (commitment_5, opening_5) = Pedersen::new(amount_5);
        let (commitment_6, opening_6) = Pedersen::new(amount_6);
        let (commitment_7, opening_7) = Pedersen::new(amount_7);
        let (commitment_8, opening_8) = Pedersen::new(amount_8);

        let proof_data = BatchedRangeProofU256Data::new(
            vec![
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            vec![
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            vec![32, 32, 32, 32, 32, 32, 32, 32],
            vec![
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
        )
        .unwrap();

        assert_eq!(
            proof_data.verify_proof().unwrap_err(),
            ProofVerificationError::RangeProof(RangeProofVerificationError::AlgebraicRelation),
        );
    }
}
