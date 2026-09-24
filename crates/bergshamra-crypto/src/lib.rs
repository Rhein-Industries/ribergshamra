#![forbid(unsafe_code)]

//! Cryptographic algorithm implementations for Bergshamra XML Security library.
//!
//! Provides traits and implementations for all crypto operations needed by
//! XML-DSig and XML-Enc: digests, signatures, block ciphers, key wrapping,
//! and key transport.

pub mod cipher;
pub mod digest;
pub mod kdf;
pub mod keyagreement;
pub mod keytransport;
pub mod keywrap;
pub mod registry;
pub mod sign;

pub use digest::DigestAlgorithm;
pub use registry::AlgorithmRegistry;

/// Convert a `riptering::Error` to a `bergshamra_core::Error`.
pub(crate) fn map_riptering_err(e: riptering::Error) -> bergshamra_core::Error {
    match e {
        riptering::Error::Crypto(s) => bergshamra_core::Error::Crypto(s),
        err @ riptering::Error::UnsupportedAlgorithm { .. } => {
            bergshamra_core::Error::UnsupportedAlgorithm(err.to_string())
        }
        riptering::Error::Key(s) => bergshamra_core::Error::Key(s),
        riptering::Error::Io(e) => bergshamra_core::Error::Io(e),
        // Handle additional error variants (e.g., Pkcs11) when the riptering
        // crate is compiled with optional features.
        #[allow(unreachable_patterns)]
        other => bergshamra_core::Error::Crypto(other.to_string()),
    }
}
