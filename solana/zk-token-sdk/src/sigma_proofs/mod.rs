//! Collection of sigma proofs that are used in the ZK Token proof program.
//!
//! Formal documentation and security proofs for the sigma proofs in this module can be found in
//! [`ZK Token proof`] program documentation.
//!
//! [`ZK Token proof`]: https://docs.solanalabs.com/runtime/zk-token-proof

pub mod errors;

#[cfg(not(target_os = "solana"))]
pub mod batched_grouped_ciphertext_validity_proof;
#[cfg(not(target_os = "solana"))]
pub mod ciphertext_ciphertext_equality_proof;
#[cfg(not(target_os = "solana"))]
pub mod ciphertext_commitment_equality_proof;
#[cfg(not(target_os = "solana"))]
pub mod fee_proof;
#[cfg(not(target_os = "solana"))]
pub mod grouped_ciphertext_validity_proof;
#[cfg(not(target_os = "solana"))]
pub mod pubkey_proof;
#[cfg(not(target_os = "solana"))]
pub mod zero_balance_proof;

#[cfg(not(target_os = "solana"))]
use {
    crate::{sigma_proofs::errors::SigmaProofVerificationError, RISTRETTO_POINT_LEN, SCALAR_LEN},
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
};

/// Deserializes an optional slice of bytes to a compressed Ristretto point.
///
/// This is a helper function for deserializing byte encodings of sigma proofs. It is designed to
/// be used with `std::slice::Chunks`.
#[cfg(not(target_os = "solana"))]
fn ristretto_point_from_optional_slice(
    optional_slice: Option<&[u8]>,
) -> Result<CompressedRistretto, SigmaProofVerificationError> {
    optional_slice
        .and_then(|slice| (slice.len() == RISTRETTO_POINT_LEN).then_some(slice))
        .map(CompressedRistretto::from_slice)
        .ok_or(SigmaProofVerificationError::Deserialization)
}

/// Deserializes an optional slice of bytes to a scalar.
///
/// This is a helper function for deserializing byte encodings of sigma proofs. It is designed to
/// be used with `std::slice::Chunks`.
#[cfg(not(target_os = "solana"))]
fn canonical_scalar_from_optional_slice(
    optional_slice: Option<&[u8]>,
) -> Result<Scalar, SigmaProofVerificationError> {
    optional_slice
        .and_then(|slice| (slice.len() == SCALAR_LEN).then_some(slice)) // if chunk is the wrong length, convert to None
        .and_then(|slice| slice.try_into().ok()) // convert to array
        .and_then(Scalar::from_canonical_bytes)
        .ok_or(SigmaProofVerificationError::Deserialization)
}
