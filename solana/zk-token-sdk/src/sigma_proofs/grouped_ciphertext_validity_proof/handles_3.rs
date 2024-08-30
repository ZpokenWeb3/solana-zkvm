//! The grouped ciphertext with 3 handles validity sigma proof system.
//!
//! This ciphertext validity proof is defined with respect to a Pedersen commitment and three
//! decryption handles. The proof certifies that a given Pedersen commitment can be decrypted using
//! ElGamal private keys that are associated with each of the three decryption handles. To generate
//! the proof, a prover must provide the Pedersen opening associated with the commitment.
//!
//! The protocol guarantees computational soundness (by the hardness of discrete log) and perfect
//! zero-knowledge in the random oracle model.
//!
//! In accordance with its application to the SPL Token program, the first decryption handle
//! associated with the proof is referred to as the "source" handle, the second as the
//! "destination" handle, and the third as the "auditor" handle.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::{
            elgamal::{DecryptHandle, ElGamalPubkey},
            pedersen::{PedersenCommitment, PedersenOpening, G, H},
        },
        sigma_proofs::{canonical_scalar_from_optional_slice, ristretto_point_from_optional_slice},
        UNIT_LEN,
    },
    curve25519_dalek::traits::MultiscalarMul,
    rand::rngs::OsRng,
    zeroize::Zeroize,
};
use {
    crate::{
        sigma_proofs::errors::{SigmaProofVerificationError, ValidityProofVerificationError},
        transcript::TranscriptProtocol,
    },
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{IsIdentity, VartimeMultiscalarMul},
    },
    merlin::Transcript,
};

/// Byte length of a grouped ciphertext validity proof for 3 handles
const GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN: usize = UNIT_LEN * 6;

/// The grouped ciphertext validity proof for 3 handles.
///
/// Contains all the elliptic curve and scalar components that make up the sigma protocol.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct GroupedCiphertext3HandlesValidityProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    Y_2: CompressedRistretto,
    Y_3: CompressedRistretto,
    z_r: Scalar,
    z_x: Scalar,
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl GroupedCiphertext3HandlesValidityProof {
    /// Creates a grouped ciphertext with 3 handles validity proof.
    ///
    /// The function does *not* hash the public keys, commitment, or decryption handles into the
    /// transcript. For security, the caller (the main protocol) should hash these public
    /// components prior to invoking this constructor.
    ///
    /// This function is randomized. It uses `OsRng` internally to generate random scalars.
    ///
    /// Note that the proof constructor does not take the actual Pedersen commitment or decryption
    /// handles as input; it only takes the associated Pedersen opening instead.
    ///
    /// * `source_pubkey` - The source ElGamal public key
    /// * `destination_pubkey` - The destination ElGamal public key
    /// * `auditor_pubkey` - The auditor ElGamal public key
    /// * `amount` - The committed message in the commitment
    /// * `opening` - The opening associated with the Pedersen commitment
    /// * `transcript` - The transcript that does the bookkeeping for the Fiat-Shamir heuristic
    pub fn new<T: Into<Scalar>>(
        source_pubkey: &ElGamalPubkey,
        destination_pubkey: &ElGamalPubkey,
        auditor_pubkey: &ElGamalPubkey,
        amount: T,
        opening: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.grouped_ciphertext_validity_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_pubkey.get_point();
        let P_destination = destination_pubkey.get_point();
        let P_auditor = auditor_pubkey.get_point();

        let x = amount.into();
        let r = opening.get_scalar();

        // generate random masking factors that also serves as nonces
        let mut y_r = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);

        let Y_0 = RistrettoPoint::multiscalar_mul(vec![&y_r, &y_x], vec![&(*H), &(*G)]).compress();
        let Y_1 = (&y_r * P_source).compress();
        let Y_2 = (&y_r * P_destination).compress();
        let Y_3 = (&y_r * P_auditor).compress();

        // record masking factors in transcript and get challenges
        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);
        transcript.append_point(b"Y_3", &Y_3);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // compute masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        y_r.zeroize();
        y_x.zeroize();

        Self {
            Y_0,
            Y_1,
            Y_2,
            Y_3,
            z_r,
            z_x,
        }
    }

    /// Verifies a grouped ciphertext with 3 handles validity proof.
    ///
    /// * `commitment` - The Pedersen commitment
    /// * `source_pubkey` - The source ElGamal public key
    /// * `destination_pubkey` - The destination ElGamal public key
    /// * `auditor_pubkey` - The auditor ElGamal public key
    /// * `source_handle` - The source decryption handle
    /// * `destination_handle` - The destination decryption handle
    /// * `auditor_handle` - The auditor decryption handle
    /// * `transcript` - The transcript that does the bookkeeping for the Fiat-Shamir heuristic
    pub fn verify(
        self,
        commitment: &PedersenCommitment,
        source_pubkey: &ElGamalPubkey,
        destination_pubkey: &ElGamalPubkey,
        auditor_pubkey: &ElGamalPubkey,
        source_handle: &DecryptHandle,
        destination_handle: &DecryptHandle,
        auditor_handle: &DecryptHandle,
        transcript: &mut Transcript,
    ) -> Result<(), ValidityProofVerificationError> {
        transcript.grouped_ciphertext_validity_proof_domain_separator();

        // include `Y_0`, `Y_1`, `Y_2` to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;
        // the point `Y_3` is defined with respect to the auditor public key and can be zero if the
        // auditor public key is zero
        transcript.append_point(b"Y_3", &self.Y_3);

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");
        let ww = &w * &w;
        let www = &w * &ww;

        let w_negated = -&w;
        let ww_negated = -&ww;
        let www_negated = -&www;

        // check the required algebraic conditions
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(SigmaProofVerificationError::Deserialization)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(SigmaProofVerificationError::Deserialization)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(SigmaProofVerificationError::Deserialization)?;
        let Y_3 = self
            .Y_3
            .decompress()
            .ok_or(SigmaProofVerificationError::Deserialization)?;

        let P_source = source_pubkey.get_point();
        let P_destination = destination_pubkey.get_point();
        let P_auditor = auditor_pubkey.get_point();

        let C = commitment.get_point();
        let D_source = source_handle.get_point();
        let D_destination = destination_handle.get_point();
        let D_auditor = auditor_handle.get_point();

        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                &self.z_r,            // z_r
                &self.z_x,            // z_x
                &(-&c),               // -c
                &-(&Scalar::one()),   // -identity
                &(&w * &self.z_r),    // w * z_r
                &(&w_negated * &c),   // -w * c
                &w_negated,           // -w
                &(&ww * &self.z_r),   // ww * z_r
                &(&ww_negated * &c),  // -ww * c
                &ww_negated,          // -ww
                &(&www * &self.z_r),  // www * z_r
                &(&www_negated * &c), // -www * c
                &www_negated,         // -www
            ],
            vec![
                &(*H),         // H
                &(*G),         // G
                C,             // C
                &Y_0,          // Y_0
                P_source,      // P_destination
                D_source,      // D_destination
                &Y_1,          // Y_1
                P_destination, // P_destination
                D_destination, // D_destination
                &Y_2,          // Y_1
                P_auditor,     // P_auditor
                D_auditor,     // D_auditor
                &Y_3,          // Y_2
            ],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(SigmaProofVerificationError::AlgebraicRelation.into())
        }
    }

    pub fn to_bytes(&self) -> [u8; GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN] {
        let mut buf = [0_u8; GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN];
        let mut chunks = buf.chunks_mut(UNIT_LEN);
        chunks.next().unwrap().copy_from_slice(self.Y_0.as_bytes());
        chunks.next().unwrap().copy_from_slice(self.Y_1.as_bytes());
        chunks.next().unwrap().copy_from_slice(self.Y_2.as_bytes());
        chunks.next().unwrap().copy_from_slice(self.Y_3.as_bytes());
        chunks.next().unwrap().copy_from_slice(self.z_r.as_bytes());
        chunks.next().unwrap().copy_from_slice(self.z_x.as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidityProofVerificationError> {
        let mut chunks = bytes.chunks(UNIT_LEN);
        let Y_0 = ristretto_point_from_optional_slice(chunks.next())?;
        let Y_1 = ristretto_point_from_optional_slice(chunks.next())?;
        let Y_2 = ristretto_point_from_optional_slice(chunks.next())?;
        let Y_3 = ristretto_point_from_optional_slice(chunks.next())?;
        let z_r = canonical_scalar_from_optional_slice(chunks.next())?;
        let z_x = canonical_scalar_from_optional_slice(chunks.next())?;

        Ok(GroupedCiphertext3HandlesValidityProof {
            Y_0,
            Y_1,
            Y_2,
            Y_3,
            z_r,
            z_x,
        })
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::encryption::{elgamal::ElGamalKeypair, pedersen::Pedersen},
    };

    #[test]
    fn test_grouped_ciphertext_3_handles_validity_proof_correctness() {
        let source_keypair = ElGamalKeypair::new_rand();
        let source_pubkey = source_keypair.pubkey();

        let destination_keypair = ElGamalKeypair::new_rand();
        let destination_pubkey = destination_keypair.pubkey();

        let auditor_keypair = ElGamalKeypair::new_rand();
        let auditor_pubkey = auditor_keypair.pubkey();

        let amount: u64 = 55;
        let (commitment, opening) = Pedersen::new(amount);

        let source_handle = source_pubkey.decrypt_handle(&opening);
        let destination_handle = destination_pubkey.decrypt_handle(&opening);
        let auditor_handle = auditor_pubkey.decrypt_handle(&opening);

        let mut prover_transcript = Transcript::new(b"Test");
        let mut verifier_transcript = Transcript::new(b"Test");

        let proof = GroupedCiphertext3HandlesValidityProof::new(
            source_pubkey,
            destination_pubkey,
            auditor_pubkey,
            amount,
            &opening,
            &mut prover_transcript,
        );

        assert!(proof
            .verify(
                &commitment,
                source_pubkey,
                destination_pubkey,
                auditor_pubkey,
                &source_handle,
                &destination_handle,
                &auditor_handle,
                &mut verifier_transcript,
            )
            .is_ok());
    }

    #[test]
    fn test_grouped_ciphertext_3_handles_validity_proof_edge_cases() {
        // if source or destination public key zeroed, then the proof should always reject
        let source_pubkey = ElGamalPubkey::try_from([0u8; 32].as_slice()).unwrap();
        let destination_pubkey = ElGamalPubkey::try_from([0u8; 32].as_slice()).unwrap();

        let auditor_keypair = ElGamalKeypair::new_rand();
        let auditor_pubkey = auditor_keypair.pubkey();

        let amount: u64 = 55;
        let (commitment, opening) = Pedersen::new(amount);

        let source_handle = destination_pubkey.decrypt_handle(&opening);
        let destination_handle = destination_pubkey.decrypt_handle(&opening);
        let auditor_handle = auditor_pubkey.decrypt_handle(&opening);

        let mut prover_transcript = Transcript::new(b"Test");
        let mut verifier_transcript = Transcript::new(b"Test");

        let proof = GroupedCiphertext3HandlesValidityProof::new(
            &source_pubkey,
            &destination_pubkey,
            auditor_pubkey,
            amount,
            &opening,
            &mut prover_transcript,
        );

        assert!(proof
            .verify(
                &commitment,
                &source_pubkey,
                &destination_pubkey,
                auditor_pubkey,
                &source_handle,
                &destination_handle,
                &auditor_handle,
                &mut verifier_transcript,
            )
            .is_err());

        // all zeroed ciphertext should still be valid
        let source_keypair = ElGamalKeypair::new_rand();
        let source_pubkey = source_keypair.pubkey();

        let destination_keypair = ElGamalKeypair::new_rand();
        let destination_pubkey = destination_keypair.pubkey();

        let auditor_keypair = ElGamalKeypair::new_rand();
        let auditor_pubkey = auditor_keypair.pubkey();

        let amount: u64 = 0;
        let commitment = PedersenCommitment::from_bytes(&[0u8; 32]).unwrap();
        let opening = PedersenOpening::from_bytes(&[0u8; 32]).unwrap();

        let source_handle = source_pubkey.decrypt_handle(&opening);
        let destination_handle = destination_pubkey.decrypt_handle(&opening);
        let auditor_handle = auditor_pubkey.decrypt_handle(&opening);

        let mut prover_transcript = Transcript::new(b"Test");
        let mut verifier_transcript = Transcript::new(b"Test");

        let proof = GroupedCiphertext3HandlesValidityProof::new(
            source_pubkey,
            destination_pubkey,
            auditor_pubkey,
            amount,
            &opening,
            &mut prover_transcript,
        );

        assert!(proof
            .verify(
                &commitment,
                source_pubkey,
                destination_pubkey,
                auditor_pubkey,
                &source_handle,
                &destination_handle,
                &auditor_handle,
                &mut verifier_transcript,
            )
            .is_ok());

        // decryption handles can be zero as long as the Pedersen commitment is valid
        let source_keypair = ElGamalKeypair::new_rand();
        let source_pubkey = source_keypair.pubkey();

        let destination_keypair = ElGamalKeypair::new_rand();
        let destination_pubkey = destination_keypair.pubkey();

        let auditor_keypair = ElGamalKeypair::new_rand();
        let auditor_pubkey = auditor_keypair.pubkey();

        let amount: u64 = 55;
        let zeroed_opening = PedersenOpening::default();

        let commitment = Pedersen::with(amount, &zeroed_opening);

        let source_handle = source_pubkey.decrypt_handle(&zeroed_opening);
        let destination_handle = destination_pubkey.decrypt_handle(&zeroed_opening);
        let auditor_handle = auditor_pubkey.decrypt_handle(&zeroed_opening);

        let mut prover_transcript = Transcript::new(b"Test");
        let mut verifier_transcript = Transcript::new(b"Test");

        let proof = GroupedCiphertext3HandlesValidityProof::new(
            source_pubkey,
            destination_pubkey,
            auditor_pubkey,
            amount,
            &opening,
            &mut prover_transcript,
        );

        assert!(proof
            .verify(
                &commitment,
                source_pubkey,
                destination_pubkey,
                auditor_pubkey,
                &source_handle,
                &destination_handle,
                &auditor_handle,
                &mut verifier_transcript,
            )
            .is_ok());
    }
}
