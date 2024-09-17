pub use bytemuck_derive::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; 32]);

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {super::*, crate::errors::Curve25519Error, curve25519_dalek::scalar::Scalar};

    impl From<&Scalar> for PodScalar {
        fn from(scalar: &Scalar) -> Self {
            Self(scalar.to_bytes())
        }
    }

    impl TryFrom<&PodScalar> for Scalar {
        type Error = Curve25519Error;

        fn try_from(pod: &PodScalar) -> Result<Self, Self::Error> {
            Scalar::from_canonical_bytes(pod.0)
                .into_option()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl From<Scalar> for PodScalar {
        fn from(scalar: Scalar) -> Self {
            Self(scalar.to_bytes())
        }
    }

    impl TryFrom<PodScalar> for Scalar {
        type Error = Curve25519Error;

        fn try_from(pod: PodScalar) -> Result<Self, Self::Error> {
            Scalar::from_canonical_bytes(pod.0)
                .into_option()
                .ok_or(Curve25519Error::PodConversion)
        }
    }
}
