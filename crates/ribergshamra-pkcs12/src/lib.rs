#![forbid(unsafe_code)]

//! PKCS#12 (.p12/.pfx) parser for the ribergshamra XML Security library.
//!
//! Supports both legacy PBE (SHA-1 + 3DES-CBC) and modern PBES2
//! (PBKDF2 + AES-256-CBC) encryption as used by OpenSSL 3.x.

mod kdf;
mod parse;

/// Zeroizing, provider-neutral PKCS#8 private-key encoding.
pub struct PrivateKeyDer(zeroize::Zeroizing<Vec<u8>>);

impl PrivateKeyDer {
    #[must_use]
    pub fn new(der: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(der))
    }
}

impl AsRef<[u8]> for PrivateKeyDer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::Deref for PrivateKeyDer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl std::fmt::Debug for PrivateKeyDer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateKeyDer")
            .field("length", &self.0.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Contents extracted from a PKCS#12 file.
#[derive(Debug)]
pub struct Pkcs12Contents {
    /// PKCS#8 DER-encoded private keys.
    pub private_keys: Vec<PrivateKeyDer>,
    /// DER-encoded X.509 certificates.
    pub certificates: Vec<Vec<u8>>,
}

/// Resource limits for importing password-protected PKCS#12 containers.
///
/// Limits apply before password derivation and while collecting structures.
/// `max_kdf_work` counts iterations multiplied by the number of derived hash
/// blocks, including separate legacy key and IV derivations; it is a work
/// budget, not a wall-clock guarantee.
#[derive(Debug, Clone, Copy)]
pub struct Pkcs12Limits {
    /// Maximum encoded container size in bytes.
    pub max_input_len: usize,
    /// Maximum UTF-8 password size in bytes.
    pub max_password_len: usize,
    /// Maximum salt size in bytes for each derivation.
    pub max_salt_len: usize,
    /// Maximum iterations for each derivation.
    pub max_iterations: u32,
    /// Maximum aggregate iteration/block work for an import.
    pub max_kdf_work: u64,
    /// Maximum ContentInfo entries in the authenticated safe.
    pub max_content_infos: usize,
    /// Maximum total SafeBag entries across all ContentInfo entries.
    pub max_bags: usize,
}

impl Default for Pkcs12Limits {
    fn default() -> Self {
        Self {
            max_input_len: 16 * 1024 * 1024,
            max_password_len: 64 * 1024,
            max_salt_len: 64 * 1024,
            max_iterations: 1_000_000,
            max_kdf_work: 10_000_000,
            max_content_infos: 128,
            max_bags: 4096,
        }
    }
}

/// Parse a PKCS#12 file, decrypting with the given password.
///
/// Uses [`Pkcs12Limits::default`]. To import a larger trusted container or
/// enforce a smaller budget, use [`parse_pkcs12_with_limits`].
pub fn parse_pkcs12(
    data: &[u8],
    password: &str,
) -> Result<Pkcs12Contents, ribergshamra_core::Error> {
    parse_pkcs12_with_limits(data, password, &Pkcs12Limits::default())
}

/// Parse a PKCS#12 file with explicit resource limits.
pub fn parse_pkcs12_with_limits(
    data: &[u8],
    password: &str,
    limits: &Pkcs12Limits,
) -> Result<Pkcs12Contents, ribergshamra_core::Error> {
    parse::parse_pfx_with_limits(data, password, limits)
}
