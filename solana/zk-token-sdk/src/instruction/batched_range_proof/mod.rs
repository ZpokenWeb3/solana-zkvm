//! The batched range proof instructions.
//!
//! A batched range proof is defined with respect to a sequence of commitments `[C_1, ..., C_N]`
//! and bit-lengths `[n_1, ..., n_N]`. It certifies that each `C_i` is a commitment to a number of
//! bit-length `n_i`.
//!
//! There are three batched range proof instructions: `VerifyBatchedRangeProof64`,
//! `VerifyBatchedRangeProof128`, and `VerifyBatchedRangeProof256`. The value `N` in
//! `VerifyBatchedRangeProof{N}` specifies the sum of the bit-lengths that the proof is certifying
//! for a sequence of commitments.
//!
//! For example to generate a batched range proof on a sequence of commitments `[C_1, C_2, C_3]` on
//! a sequence of bit-lengths `[32, 32, 64]`, one must use `VerifyBatchedRangeProof128` as 128 is
//! the sum of all bit-lengths.
//!
//! The maximum number of commitments is fixed at 8. Each bit-length in `[n_1, ..., n_N]` must be a
//! power-of-two positive integer less than 128.

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

use crate::zk_token_elgamal::pod;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        errors::{ProofGenerationError, ProofVerificationError},
    },
    bytemuck::{bytes_of, Zeroable},
    curve25519_dalek::traits::IsIdentity,
    merlin::Transcript,
    std::convert::TryInto,
};

const MAX_COMMITMENTS: usize = 8;

/// A bit length in a batched range proof must be at most 128.
///
/// A 256-bit range proof on a single Pedersen commitment is meaningless and hence enforce an upper
/// bound as the largest power-of-two number less than 256.
#[cfg(not(target_os = "solana"))]
const MAX_SINGLE_BIT_LENGTH: usize = 128;

/// The context data needed to verify a range-proof for a Pedersen committed value.
///
/// The context data is shared by all `VerifyBatchedRangeProof{N}` instructions.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofContext {
    pub commitments: [pod::PedersenCommitment; MAX_COMMITMENTS],
    pub bit_lengths: [u8; MAX_COMMITMENTS],
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofContext {
    fn new_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"BatchedRangeProof");
        transcript.append_message(b"commitments", bytes_of(&self.commitments));
        transcript.append_message(b"bit-lengths", bytes_of(&self.bit_lengths));
        transcript
    }

    fn new(
        commitments: &[&PedersenCommitment],
        amounts: &[u64],
        bit_lengths: &[usize],
        openings: &[&PedersenOpening],
    ) -> Result<Self, ProofGenerationError> {
        // the number of commitments is capped at 8
        let num_commitments = commitments.len();
        if num_commitments > MAX_COMMITMENTS
            || num_commitments != amounts.len()
            || num_commitments != bit_lengths.len()
            || num_commitments != openings.len()
        {
            return Err(ProofGenerationError::IllegalCommitmentLength);
        }

        let mut pod_commitments = [pod::PedersenCommitment::zeroed(); MAX_COMMITMENTS];
        for (i, commitment) in commitments.iter().enumerate() {
            // all-zero commitment is invalid
            if commitment.get_point().is_identity() {
                return Err(ProofGenerationError::InvalidCommitment);
            }
            pod_commitments[i] = pod::PedersenCommitment(commitment.to_bytes());
        }

        let mut pod_bit_lengths = [0; MAX_COMMITMENTS];
        for (i, bit_length) in bit_lengths.iter().enumerate() {
            pod_bit_lengths[i] = (*bit_length)
                .try_into()
                .map_err(|_| ProofGenerationError::IllegalAmountBitLength)?;
        }

        Ok(BatchedRangeProofContext {
            commitments: pod_commitments,
            bit_lengths: pod_bit_lengths,
        })
    }
}

#[cfg(not(target_os = "solana"))]
impl TryInto<(Vec<PedersenCommitment>, Vec<usize>)> for BatchedRangeProofContext {
    type Error = ProofVerificationError;

    fn try_into(self) -> Result<(Vec<PedersenCommitment>, Vec<usize>), Self::Error> {
        let commitments = self
            .commitments
            .into_iter()
            .take_while(|commitment| *commitment != pod::PedersenCommitment::zeroed())
            .map(|commitment| commitment.try_into())
            .collect::<Result<Vec<PedersenCommitment>, _>>()
            .map_err(|_| ProofVerificationError::ProofContext)?;

        let bit_lengths: Vec<_> = self
            .bit_lengths
            .into_iter()
            .take(commitments.len())
            .map(|bit_length| bit_length as usize)
            .collect();

        Ok((commitments, bit_lengths))
    }
}
