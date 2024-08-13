//! Plain Old Data types for the AES128-GCM-SIV authenticated encryption scheme.

#[cfg(not(target_os = "solana"))]
use crate::{encryption::auth_encryption::AeCiphertext, errors::AuthenticatedEncryptionError};
use {
    crate::encryption::{pod::impl_from_str, AE_CIPHERTEXT_LEN},
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    std::fmt,
};

/// Maximum length of a base64 encoded authenticated encryption ciphertext
const AE_CIPHERTEXT_MAX_BASE64_LEN: usize = 48;

/// The `AeCiphertext` type as a `Pod`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodAeCiphertext(pub(crate) [u8; AE_CIPHERTEXT_LEN]);

// `PodAeCiphertext` is a wrapper type for a byte array, which is both `Pod` and `Zeroable`. However,
// the marker traits `bytemuck::Pod` and `bytemuck::Zeroable` can only be derived for power-of-two
// length byte arrays. Directly implement these traits for `PodAeCiphertext`.
unsafe impl Zeroable for PodAeCiphertext {}
unsafe impl Pod for PodAeCiphertext {}

impl fmt::Debug for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodAeCiphertext,
    BYTES_LEN = AE_CIPHERTEXT_LEN,
    BASE64_LEN = AE_CIPHERTEXT_MAX_BASE64_LEN
);

impl Default for PodAeCiphertext {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<AeCiphertext> for PodAeCiphertext {
    fn from(decoded_ciphertext: AeCiphertext) -> Self {
        Self(decoded_ciphertext.to_bytes())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodAeCiphertext> for AeCiphertext {
    type Error = AuthenticatedEncryptionError;

    fn try_from(pod_ciphertext: PodAeCiphertext) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(AuthenticatedEncryptionError::Deserialization)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::encryption::auth_encryption::AeKey, std::str::FromStr};

    #[test]
    fn ae_ciphertext_fromstr() {
        let ae_key = AeKey::new_rand();
        let expected_ae_ciphertext: PodAeCiphertext = ae_key.encrypt(0_u64).into();

        let ae_ciphertext_base64_str = format!("{}", expected_ae_ciphertext);
        let computed_ae_ciphertext = PodAeCiphertext::from_str(&ae_ciphertext_base64_str).unwrap();

        assert_eq!(expected_ae_ciphertext, computed_ae_ciphertext);
    }
}
