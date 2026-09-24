#![forbid(unsafe_code)]

//! Public facade for ribergshamra XML security.
//!
//! This crate re-exports the main ribergshamra subcrates and the most common
//! entry points for XML Signature and XML Encryption work. For signing and
//! verification, start with [`DsigContext`], [`sign`], [`verify`], and
//! [`verify_all`]. For encryption and decryption, start with [`EncContext`],
//! [`encrypt`], [`decrypt`], and [`decrypt_to_bytes`].
//!
//! Lower-level modules remain available when callers need direct access to
//! canonical XML (`c14n`), key loading and lookup (`keys`), transform handling
//! (`transforms`), or algorithm implementations (`crypto`).

/// Canonical XML support, including inclusive, exclusive, and C14N 1.1 modes.
pub use ribergshamra_c14n as c14n;
/// Core shared types, XML security namespace constants, and the error type.
pub use ribergshamra_core as core;
/// Cryptographic algorithm implementations and registries.
pub use ribergshamra_crypto as crypto;
/// XML Digital Signature signing and verification.
pub use ribergshamra_dsig as dsig;
/// XML Encryption encryption and decryption.
pub use ribergshamra_enc as enc;
/// Key representations, key stores, KeyInfo helpers, and X.509 validation.
pub use ribergshamra_keys as keys;
/// XML Signature transform implementations and transform pipelines.
pub use ribergshamra_transforms as transforms;
/// XML document helpers and node-set support used by transforms and C14N.
pub use ribergshamra_xml as xml;

/// ribergshamra's shared error type.
pub use ribergshamra_core::Error;
/// Digital signature configuration and verification result types.
pub use ribergshamra_dsig::{DsigContext, VerifiedKeyInfo, VerifiedReference, VerifyResult};
/// Encryption configuration.
pub use ribergshamra_enc::EncContext;
/// Key types and the in-memory key manager.
pub use ribergshamra_keys::{Key, KeyData, KeyUsage, KeysManager};
/// Compile-time provider metadata, capabilities, and explicit initialization.
pub use riptering::{
    backend_info, capabilities, initialize_backend, supports, BackendId, BackendInfo, Capability,
    FipsStatus, Operation, SoftwareKey, TlsBackendId,
};

/// Sign an XML signature template.
pub use ribergshamra_dsig::sign::sign;
/// Verify the first signature, or all signatures, in an XML document.
pub use ribergshamra_dsig::verify::{verify, verify_all};
/// Decrypt XML Encryption content as UTF-8 text or raw bytes.
pub use ribergshamra_enc::decrypt::{decrypt, decrypt_to_bytes};
/// Encrypt bytes into an XML Encryption template.
pub use ribergshamra_enc::encrypt::encrypt;
