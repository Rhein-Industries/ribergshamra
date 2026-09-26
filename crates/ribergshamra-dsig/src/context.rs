#![forbid(unsafe_code)]

//! DSig context — holds keys and configuration for signature operations.

use ribergshamra_core::Error;
use ribergshamra_keys::KeysManager;
use riptering::traits::{Signer, Verifier};

/// Maximum number of bytes loaded from one detached-reference or retrieved
/// certificate file. Files must also be regular files.
pub const MAX_EXTERNAL_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Context for XML-DSig operations.
pub struct DsigContext {
    /// Keys manager for key lookup.
    pub keys_manager: KeysManager,
    /// Additional ID attribute names to register.
    pub id_attrs: Vec<String>,
    /// Explicit URL-to-file mappings for external URI resolution.
    ///
    /// Prefer these mappings for detached `<Reference>` bytes when the URI is
    /// not a simple document-relative file. Signing and verification read local
    /// relative paths only with an explicit `base_dir`; neither falls back to
    /// the process's working directory. External files must be regular
    /// files no larger than [`MAX_EXTERNAL_FILE_BYTES`]. Verifier debug output
    /// redacts detached bytes.
    pub url_maps: Vec<(String, String)>,
    /// Minimum HMAC output length in bits (0 = use spec default).
    pub hmac_min_out_len: usize,
    /// Debug mode: print pre-digest and pre-signature data to stderr.
    pub debug: bool,
    /// Base directory for signing-time relative references, verifier
    /// document-relative references, and retrieval-method key resolution.
    ///
    /// Signing, verification, and key retrieval require this to authorize
    /// relative file access; `None` disables relative filesystem reads. This is not an
    /// unrestricted filesystem root: URI schemes, absolute paths, `..`
    /// traversal, and symlink escapes are rejected for local-file lookup.
    /// On Unix, reads walk canonical path components through directory handles
    /// without following further symlinks. On other platforms, callers must
    /// keep the configured directories unchanged during each operation.
    pub base_dir: Option<String>,
    /// Insecure mode: skip all certificate validation.
    pub insecure: bool,
    /// Verify keys: validate certificates for keys loaded from files.
    pub verify_keys: bool,
    /// Override verification time (format: "YYYY-MM-DD+HH:MM:SS").
    pub verification_time: Option<String>,
    /// Skip X.509 time checks (NotBefore/NotAfter).
    pub skip_time_checks: bool,
    /// Whether --enabled-key-data includes x509.
    pub enabled_key_data_x509: bool,
    /// Allow raw inline `<KeyValue>` / `<DEREncodedKeyValue>` even when trust
    /// anchors are configured.
    ///
    /// Keep this `false` for normal verification. It exists for xmlsec
    /// compatibility suites that intentionally combine trusted CA flags with
    /// raw inline test keys.
    pub allow_raw_inline_keyinfo_with_trust_anchors: bool,
    /// When true, only use keys from the KeysManager for verification.
    /// Skip extraction of inline keys from KeyInfo (KeyValue, X509Certificate, etc.).
    /// This is the secure mode for SAML: only trust pre-configured IdP keys,
    /// not whatever an attacker embeds in the XML signature's KeyInfo.
    pub trusted_keys_only: bool,
    /// When true, enforce that each reference target is either the document element,
    /// an ancestor of the Signature, or a sibling of the Signature. This prevents
    /// XML Signature Wrapping (XSW) attacks where signed content is moved to an
    /// unexpected position in the document.
    pub strict_verification: bool,
    /// When true, a valid `SignatureValue` is still reported invalid unless at
    /// least one `Reference` digest was computed locally and every reference
    /// digest was locally verified.
    ///
    /// Disable this only for detached-content profiles, such as WS-Security
    /// `cid:` attachments, after the caller verifies those external bytes
    /// out-of-band.
    pub require_reference_digests: bool,
    /// Optional HSM-backed signer. When set, bypasses KeysManager for signing.
    pub hsm_signer: Option<Box<dyn Signer>>,
    /// Optional HSM-backed verifier. When set, bypasses KeysManager for verification.
    pub hsm_verifier: Option<Box<dyn Verifier>>,
}

impl std::fmt::Debug for DsigContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format `keys_manager` directly: `KeysManager`/`Key` derive
        // `Debug`, which would print private RSA/EC key material and raw
        // HMAC/AES bytes into logs and crash reports. Redact to a key count.
        f.debug_struct("DsigContext")
            .field(
                "keys_manager",
                &format_args!("<{} key(s), redacted>", self.keys_manager.len()),
            )
            .field("id_attrs", &self.id_attrs)
            .field("url_maps", &self.url_maps)
            .field("hmac_min_out_len", &self.hmac_min_out_len)
            .field("debug", &self.debug)
            .field("base_dir", &self.base_dir)
            .field("insecure", &self.insecure)
            .field("verify_keys", &self.verify_keys)
            .field("verification_time", &self.verification_time)
            .field("skip_time_checks", &self.skip_time_checks)
            .field("enabled_key_data_x509", &self.enabled_key_data_x509)
            .field(
                "allow_raw_inline_keyinfo_with_trust_anchors",
                &self.allow_raw_inline_keyinfo_with_trust_anchors,
            )
            .field("trusted_keys_only", &self.trusted_keys_only)
            .field("strict_verification", &self.strict_verification)
            .field("require_reference_digests", &self.require_reference_digests)
            .field(
                "hsm_signer",
                &self.hsm_signer.as_ref().map(|_| "<hsm_signer>"),
            )
            .field(
                "hsm_verifier",
                &self.hsm_verifier.as_ref().map(|_| "<hsm_verifier>"),
            )
            .finish()
    }
}

impl DsigContext {
    /// Create a new DSig context with secure defaults.
    ///
    /// The defaults are hardened for federated identity (SAML, WS-Security):
    /// - **`trusted_keys_only = true`** — reject inline keys from `<KeyInfo>` (KeyValue,
    ///   X509Certificate, etc.); only use pre-configured keys from the `KeysManager`.
    /// - **`strict_verification = true`** — reject references to nodes that are not
    ///   ancestors, siblings, or the document element relative to the `<Signature>`
    ///   (XSW protection).
    /// - **`hmac_min_out_len = 160`** — enforce minimum HMAC output length of 160 bits
    ///   to prevent truncation attacks (CVE-2009-0217).
    /// - **`require_reference_digests = true`** — require the signed
    ///   `<SignedInfo>` to contain at least one `<Reference>` and require every
    ///   `<Reference>` digest to be verified locally.
    ///
    /// Use [`new_permissive()`](Self::new_permissive) if you need inline-key and
    /// relaxed structural behavior for self-contained signatures.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            trusted_keys_only: true,
            strict_verification: true,
            hmac_min_out_len: 160,
            ..Self::new_permissive(keys_manager)
        }
    }

    /// Create a DSig context with permissive key and structure defaults.
    ///
    /// This accepts inline keys from `<KeyInfo>`, does not enforce reference positions,
    /// and does not enforce a minimum HMAC output length. It still requires local
    /// reference-digest coverage by default so a valid `SignatureValue` cannot be
    /// confused for payload integrity when no XML bytes were digested.
    ///
    /// Suitable for document signing with self-contained signatures, or when the
    /// caller overrides all security-relevant fields explicitly.
    ///
    /// **For SAML, WS-Security, or any protocol with pre-established key trust, use
    /// [`new()`](Self::new) instead.**
    pub fn new_permissive(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            id_attrs: Vec::new(),
            url_maps: Vec::new(),
            hmac_min_out_len: 0,
            debug: false,
            base_dir: None,
            insecure: false,
            verify_keys: false,
            verification_time: None,
            skip_time_checks: false,
            enabled_key_data_x509: false,
            allow_raw_inline_keyinfo_with_trust_anchors: false,
            trusted_keys_only: false,
            strict_verification: false,
            require_reference_digests: true,
            hsm_signer: None,
            hsm_verifier: None,
        }
    }

    /// Add an ID attribute name to register during processing.
    pub fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Map an external URI to a local file path.
    ///
    /// Use this for detached `<Reference>` values that are external URIs or
    /// require a path outside the document-adjacent relative-file policy.
    /// Resolution matches the URI exactly, or matches the same URI followed by
    /// a `#fragment` suffix.
    pub fn add_url_map(&mut self, url: &str, file_path: &str) {
        self.url_maps.push((url.to_owned(), file_path.to_owned()));
    }

    /// Set debug mode (builder style).
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set insecure mode (builder style).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Set verify keys (builder style).
    pub fn with_verify_keys(mut self, verify_keys: bool) -> Self {
        self.verify_keys = verify_keys;
        self
    }

    /// Set verification time override (builder style).
    pub fn with_verification_time(mut self, time: impl Into<String>) -> Self {
        self.verification_time = Some(time.into());
        self
    }

    /// Set skip time checks (builder style).
    pub fn with_skip_time_checks(mut self, skip: bool) -> Self {
        self.skip_time_checks = skip;
        self
    }

    /// Set enabled key data x509 (builder style).
    pub fn with_enabled_key_data_x509(mut self, enabled: bool) -> Self {
        self.enabled_key_data_x509 = enabled;
        self
    }

    /// Set whether raw inline KeyInfo keys may satisfy verification when trust
    /// anchors are configured.
    ///
    /// This is a compatibility escape hatch for xmlsec interop suites. Leave it
    /// disabled for normal verification so a raw document-controlled `<KeyValue>`
    /// cannot bypass configured trust anchors.
    pub fn with_allow_raw_inline_keyinfo_with_trust_anchors(mut self, allow: bool) -> Self {
        self.allow_raw_inline_keyinfo_with_trust_anchors = allow;
        self
    }

    /// Set trusted keys only (builder style).
    pub fn with_trusted_keys_only(mut self, trusted: bool) -> Self {
        self.trusted_keys_only = trusted;
        self
    }

    /// Set strict verification (builder style).
    pub fn with_strict_verification(mut self, strict: bool) -> Self {
        self.strict_verification = strict;
        self
    }

    /// Set whether verification requires local reference-digest coverage.
    ///
    /// Keep this enabled for ordinary XML signature verification. Set it to
    /// `false` only when the caller has a separate policy for validating
    /// detached content, such as `cid:` attachment bytes.
    pub fn with_require_reference_digests(mut self, require: bool) -> Self {
        self.require_reference_digests = require;
        self
    }

    /// Set minimum HMAC output length in bits (builder style).
    pub fn with_hmac_min_out_len(mut self, bits: usize) -> Self {
        self.hmac_min_out_len = bits;
        self
    }

    /// Set base directory for signing-time relative URIs, verifier
    /// document-relative URIs, and key retrieval.
    ///
    /// Signing, verification, and key retrieval resolve simple relative paths
    /// only under this directory. URI schemes, absolute paths, parent traversal,
    /// and symlink escapes are rejected for relative-file lookup.
    pub fn with_base_dir(mut self, dir: impl Into<String>) -> Self {
        self.base_dir = Some(dir.into());
        self
    }

    /// Set an HSM-backed signer (builder style).
    ///
    /// When set, signing operations bypass the `KeysManager` and delegate
    /// to the provided [`riptering::Signer`] implementation. Key material
    /// never leaves the HSM.
    pub fn with_hsm_signer(mut self, signer: Box<dyn riptering::Signer>) -> Self {
        self.hsm_signer = Some(signer);
        self
    }

    /// Set an HSM-backed verifier (builder style).
    ///
    /// When set, signature verification bypasses the `KeysManager` and
    /// delegates to the provided [`riptering::Verifier`] implementation.
    pub fn with_hsm_verifier(mut self, verifier: Box<dyn riptering::Verifier>) -> Self {
        self.hsm_verifier = Some(verifier);
        self
    }
}

/// Return whether a configured URL map applies to a `<Reference URI>`.
///
/// URL maps are exact by default. The only non-exact match accepted here is a
/// fragment suffix on the same mapped resource, such as mapping
/// `https://example.test/doc.xml` for `https://example.test/doc.xml#payload`.
/// This avoids treating lookalike prefixes such as
/// `https://example.test.evil/...` as the mapped resource.
pub(crate) fn url_map_matches(uri: &str, map_url: &str) -> bool {
    uri == map_url
        || uri
            .strip_prefix(map_url)
            .is_some_and(|suffix| suffix.starts_with('#'))
}

/// Bound document-selected transform work before entering either digest path.
pub(crate) fn validate_reference_transforms(
    doc: &uppsala::Document<'_>,
    transforms: Option<uppsala::NodeId>,
) -> Result<(), Error> {
    let count = transforms.map_or(0, |node| {
        doc.children_iter(node)
            .filter(|&child| {
                doc.element(child).is_some_and(|element| {
                    element.name.local_name.as_ref() == ribergshamra_core::ns::node::TRANSFORM
                })
            })
            .count()
    });
    ribergshamra_transforms::pipeline::validate_transform_count(
        count,
        ribergshamra_transforms::pipeline::DEFAULT_MAX_TRANSFORMS,
    )
}

/// Return whether `uri` begins with an RFC-style scheme name.
///
/// This keeps `urn:...` and `http:...` out of local-file fallback paths even
/// when they do not contain `://`.
pub(crate) fn uri_has_scheme(uri: &str) -> bool {
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Validate a `<Reference URI>` before considering local relative-file lookup.
///
/// Absolute paths, Windows path prefixes, root components, and parent traversal
/// are rejected before scheme detection. That ordering matters on Windows,
/// where drive-letter paths such as `C:\secret.txt` can otherwise look like a
/// one-letter URI scheme.
pub(crate) fn local_reference_relative_path(uri: &str) -> Result<Option<&std::path::Path>, Error> {
    let path = std::path::Path::new(uri);
    if path.is_absolute() {
        return Err(Error::InvalidUri(format!(
            "absolute local file Reference URI not allowed: {uri}"
        )));
    }

    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                return Err(Error::InvalidUri(format!(
                    "absolute local file Reference URI not allowed: {uri}"
                )));
            }
            std::path::Component::ParentDir => {
                return Err(Error::InvalidUri(format!(
                    "parent-directory Reference URI not allowed: {uri}"
                )));
            }
            _ => {}
        }
    }

    if uri_has_scheme(uri) {
        return Ok(None);
    }

    Ok(Some(path))
}

/// Read `relative_path` under `base` only when canonical resolution stays below
/// that same canonical base directory.
///
/// Initial canonicalization permits symlinks whose targets stay inside the
/// base. On Unix the subsequent read is anchored to the canonical base's open
/// directory handle, and every remaining path component is opened without
/// following symlinks. Containment is never checked on one path and then used
/// to authorize a fresh path-based read.
///
/// On non-Unix platforms the standard-library fallback requires caller-owned
/// directories that are not concurrently mutated. This policy does not freeze
/// file contents or prevent a directory owner from creating hard links.
pub(crate) fn read_existing_relative_file(
    base: &std::path::Path,
    relative_path: &std::path::Path,
    uri: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let full = base.join(relative_path);
    let canonical_full = match full.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(external_file_io_error(&full, error)),
    };
    let canonical_base = base
        .canonicalize()
        .map_err(|error| external_file_io_error(base, error))?;
    let relative = canonical_full.strip_prefix(&canonical_base).map_err(|_| {
        Error::InvalidUri(format!(
            "local file Reference URI escapes base directory: {uri}"
        ))
    })?;
    #[cfg(not(unix))]
    validate_external_file_path(&canonical_full)?;

    #[cfg(unix)]
    let file = {
        let directory = open_canonical_directory(&canonical_base)?;
        open_relative_external_file(&directory, relative, &canonical_full)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(canonical_base.join(relative))
        .map_err(|error| external_file_io_error(&canonical_full, error))?;

    read_external_file_handle(file, &canonical_full).map(Some)
}

/// Read externally referenced bytes with a regular-file check and a hard cap.
///
/// Check the path before opening it so devices, sockets, and FIFOs are rejected
/// without reading them. Unix opens walk every canonical parent component with
/// `O_DIRECTORY | O_NOFOLLOW` and open the final component with `O_NOFOLLOW |
/// O_NONBLOCK`; replacing any component with a symlink cannot redirect the
/// open. Initial symlinks in caller-selected mappings remain supported by
/// canonicalizing the mapping once before that walk.
///
/// The opened handle is checked independently, and the read has its own cap so
/// concurrent file growth cannot exceed the byte limit. On non-Unix platforms,
/// callers must keep mapped directories unchanged during each operation.
pub(crate) fn read_regular_external_file(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    let canonical_path = path
        .canonicalize()
        .map_err(|error| external_file_io_error(path, error))?;
    #[cfg(not(unix))]
    validate_external_file_path(&canonical_path)?;

    #[cfg(unix)]
    let file = {
        let parent = canonical_path.parent().ok_or_else(|| {
            Error::InvalidUri(format!(
                "external URI file has no parent: {}",
                path.display()
            ))
        })?;
        let name = canonical_path.file_name().ok_or_else(|| {
            Error::InvalidUri(format!("external URI file has no name: {}", path.display()))
        })?;
        let directory = open_canonical_directory(parent)?;
        open_relative_external_file(&directory, std::path::Path::new(name), path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(&canonical_path)
        .map_err(|error| external_file_io_error(path, error))?;

    read_external_file_handle(file, path)
}

#[cfg(not(unix))]
fn validate_external_file_path(path: &std::path::Path) -> Result<(), Error> {
    let metadata = std::fs::metadata(path).map_err(|error| external_file_io_error(path, error))?;
    validate_external_file_metadata(&metadata, path)
}

fn read_external_file_handle(
    file: std::fs::File,
    path: &std::path::Path,
) -> Result<Vec<u8>, Error> {
    use std::io::Read;

    let metadata = file
        .metadata()
        .map_err(|error| external_file_io_error(path, error))?;
    validate_external_file_metadata(&metadata, path)?;

    let mut bytes = Vec::new();
    file.take(MAX_EXTERNAL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| external_file_io_error(path, error))?;
    if bytes.len() as u64 > MAX_EXTERNAL_FILE_BYTES {
        return Err(external_file_size_error(path));
    }
    Ok(bytes)
}

/// Start at the filesystem root and open each canonical directory component
/// separately. Holding each parent handle avoids re-resolving earlier names.
#[cfg(unix)]
fn open_canonical_directory(path: &std::path::Path) -> Result<std::fs::File, Error> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::path::Component;

    if !path.is_absolute() {
        return Err(Error::InvalidUri(format!(
            "external URI directory is not absolute: {}",
            path.display()
        )));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = std::fs::File::from(
        open(std::path::Path::new("/"), flags, Mode::empty())
            .map_err(|error| external_file_io_error(path, error))?,
    );
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = std::fs::File::from(
                    openat(&directory, name, flags, Mode::empty())
                        .map_err(|error| external_file_io_error(path, error))?,
                );
            }
            _ => return Err(external_file_component_error(path)),
        }
    }
    Ok(directory)
}

/// Open a canonical target relative to an already authorized base directory.
/// Directory and leaf symlinks are rejected even when they point inside it;
/// supported initial symlinks were resolved by the preceding canonicalization.
#[cfg(unix)]
fn open_relative_external_file(
    directory: &std::fs::File,
    relative: &std::path::Path,
    display_path: &std::path::Path,
) -> Result<std::fs::File, Error> {
    use rustix::fs::{openat, statat, AtFlags, FileType, Mode, OFlags};
    use std::path::Component;

    let mut directory = directory
        .try_clone()
        .map_err(|error| external_file_io_error(display_path, error))?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(external_file_component_error(display_path));
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if components.peek().is_some() {
            flags |= OFlags::DIRECTORY;
        } else {
            // Check through the same held parent used for opening; a path-based
            // metadata check would reintroduce ambient parent resolution.
            let metadata = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| external_file_io_error(display_path, error))?;
            if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
                return Err(external_file_type_error(display_path));
            }
            let size = u64::try_from(metadata.st_size)
                .map_err(|_| external_file_size_error(display_path))?;
            if size > MAX_EXTERNAL_FILE_BYTES {
                return Err(external_file_size_error(display_path));
            }
            flags |= OFlags::NONBLOCK;
        }
        let file = std::fs::File::from(
            openat(&directory, name, flags, Mode::empty())
                .map_err(|error| external_file_io_error(display_path, error))?,
        );
        if components.peek().is_none() {
            return Ok(file);
        }
        directory = file;
    }
    Err(external_file_component_error(display_path))
}

#[cfg(unix)]
fn external_file_component_error(path: &std::path::Path) -> Error {
    Error::InvalidUri(format!(
        "external URI path must contain only canonical file components: {}",
        path.display()
    ))
}

fn external_file_io_error(path: &std::path::Path, error: impl std::fmt::Display) -> Error {
    Error::Other(format!("{}: {error}", path.display()))
}

fn validate_external_file_metadata(
    metadata: &std::fs::Metadata,
    path: &std::path::Path,
) -> Result<(), Error> {
    if !metadata.is_file() {
        return Err(external_file_type_error(path));
    }
    if metadata.len() > MAX_EXTERNAL_FILE_BYTES {
        return Err(external_file_size_error(path));
    }
    Ok(())
}

fn external_file_type_error(path: &std::path::Path) -> Error {
    Error::InvalidUri(format!(
        "external URI file must be a regular file: {}",
        path.display()
    ))
}

fn external_file_size_error(path: &std::path::Path) -> Error {
    Error::InvalidUri(format!(
        "external URI file exceeds {MAX_EXTERNAL_FILE_BYTES}-byte limit: {}",
        path.display()
    ))
}

#[cfg(test)]
mod external_file_policy_tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "ribergshamra-external-policy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn nested_regular_file_and_missing_relative_file() {
        let directory = TestDirectory::new();
        std::fs::create_dir(directory.0.join("nested")).unwrap();
        let path = directory.0.join("nested/data");
        std::fs::write(&path, b"bounded detached bytes").unwrap();
        assert_eq!(
            read_existing_relative_file(&directory.0, Path::new("nested/data"), "nested/data")
                .unwrap(),
            Some(b"bounded detached bytes".to_vec())
        );
        assert_eq!(
            read_existing_relative_file(&directory.0, Path::new("missing"), "missing").unwrap(),
            None
        );
        assert_eq!(
            read_regular_external_file(&path).unwrap(),
            b"bounded detached bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn initial_contained_symlinks_and_explicit_mapped_symlinks_remain_supported() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let outside = TestDirectory::new();
        std::fs::create_dir(directory.0.join("nested")).unwrap();
        std::fs::write(directory.0.join("nested/data"), b"inside").unwrap();
        std::fs::write(outside.0.join("data"), b"explicitly mapped").unwrap();
        symlink("nested/data", directory.0.join("leaf-link")).unwrap();
        symlink("nested", directory.0.join("directory-link")).unwrap();
        symlink(outside.0.join("data"), directory.0.join("outside-link")).unwrap();
        for relative in ["leaf-link", "directory-link/data"] {
            assert_eq!(
                read_existing_relative_file(&directory.0, Path::new(relative), relative).unwrap(),
                Some(b"inside".to_vec())
            );
        }
        assert!(read_existing_relative_file(
            &directory.0,
            Path::new("outside-link"),
            "outside-link"
        )
        .is_err());
        // An exact caller-selected mapping authorizes its selected target.
        assert_eq!(
            read_regular_external_file(&directory.0.join("outside-link")).unwrap(),
            b"explicitly mapped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_directory_walk_rejects_symlink_parent_components() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        std::fs::create_dir_all(directory.0.join("actual/child")).unwrap();
        symlink("actual", directory.0.join("alias")).unwrap();
        assert!(open_canonical_directory(&directory.0.join("actual/child")).is_ok());
        assert!(open_canonical_directory(&directory.0.join("alias/child")).is_err());
        assert!(open_canonical_directory(Path::new("relative")).is_err());
        assert!(open_canonical_directory(&directory.0.join("actual/../actual")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn anchored_file_open_rejects_leaf_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        std::fs::create_dir(directory.0.join("nested")).unwrap();
        std::fs::write(directory.0.join("nested/data"), b"inside").unwrap();
        symlink("nested/data", directory.0.join("leaf-link")).unwrap();
        symlink("nested", directory.0.join("directory-link")).unwrap();
        let handle = open_canonical_directory(&directory.0).unwrap();
        for relative in [
            "leaf-link",
            "directory-link/data",
            "nested",
            "../data",
            "/data",
            "",
        ] {
            assert!(
                open_relative_external_file(&handle, Path::new(relative), &directory.0).is_err(),
                "accepted noncanonical component path {relative:?}"
            );
        }
        let file = open_relative_external_file(
            &handle,
            Path::new("nested/data"),
            &directory.0.join("nested/data"),
        )
        .unwrap();
        assert_eq!(
            read_external_file_handle(file, &directory.0).unwrap(),
            b"inside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_file_handle_is_nonblocking_and_close_on_exec() {
        let directory = TestDirectory::new();
        let path = directory.0.join("data");
        std::fs::write(&path, b"inside").unwrap();
        let directory_handle = open_canonical_directory(&directory.0).unwrap();
        let file =
            open_relative_external_file(&directory_handle, Path::new("data"), &path).unwrap();
        assert!(rustix::fs::fcntl_getfl(&file)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK));
        assert!(rustix::io::fcntl_getfd(&file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn opened_handle_rejects_nonregular_and_oversized_files() {
        let directory = TestDirectory::new();
        assert!(read_regular_external_file(&directory.0).is_err());
        let path = directory.0.join("large");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_EXTERNAL_FILE_BYTES).unwrap();
        assert!(validate_external_file_metadata(&file.metadata().unwrap(), &path).is_ok());
        file.set_len(MAX_EXTERNAL_FILE_BYTES + 1).unwrap();
        assert!(read_external_file_handle(file, &path).is_err());
        assert!(read_regular_external_file(&path).is_err());
    }
}
