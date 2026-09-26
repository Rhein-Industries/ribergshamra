#![forbid(unsafe_code)]

//! X.509 certificate chain validation.
//!
//! Validates leaf certificates against trusted roots with optional intermediate
//! certificates. Supports time override, CRL checking, and chain building.
//!
//! This module is a facade over [`ritsp_ltv`] — the shared trust/validation
//! infrastructure used across the e-signing family of crates.

use der::{Decode, Encode};
use ribergshamra_core::Error;
use ritsp_ltv::crypto::verify::SignaturePolicy;
use ritsp_ltv::trust::{build_chain_from_pool_with_policy, trust_anchor_subjects, TrustStore};
use x509_cert::Certificate;

/// The signature-algorithm policy applied to certificate-chain verification.
///
/// When ribergshamra is built with the `legacy-algorithms` feature, certificate
/// signatures over weak/deprecated digests (MD5/SHA-1/SHA-224) are accepted so
/// historical XML-DSig interop material (the merlin/phaos/aleksey/xmldsig11 test
/// corpora, all SHA-1-era) validates. Without that feature the strict,
/// fail-closed ritsp-ltv default is used and weak-digest certificate chains are
/// rejected. This mirrors how ribergshamra already gates legacy digest/signature
/// support elsewhere behind the same feature.
fn cert_signature_policy() -> SignaturePolicy {
    #[cfg(feature = "legacy-algorithms")]
    {
        SignaturePolicy::allow_legacy()
    }
    #[cfg(not(feature = "legacy-algorithms"))]
    {
        SignaturePolicy::strict()
    }
}

/// Configuration for X.509 certificate chain validation.
pub struct CertValidationConfig<'a> {
    /// Trusted CA certificates (DER-encoded).
    pub trusted_certs: &'a [Vec<u8>],
    /// Untrusted intermediate certificates (DER-encoded).
    pub untrusted_certs: &'a [Vec<u8>],
    /// Complete, direct-issuer CRLs (DER-encoded). Configured CRLs must include
    /// applicable authenticated evidence; delta and partitioned CRLs reject.
    pub crls: &'a [Vec<u8>],
    /// Override verification time (format: "YYYY-MM-DD+HH:MM:SS").
    pub verification_time: Option<&'a str>,
    /// Skip certificate and CRL time validity checks. This diagnostic option
    /// permits stale/future evidence; CRL authentication and scope still apply.
    pub skip_time_checks: bool,
}

/// Validate a certificate chain from a leaf cert to a trusted root.
///
/// `leaf_der` is the DER-encoded leaf certificate.
/// `additional_certs` are extra certs from the XML (the full x509_chain from KeyInfo).
/// Returns `Ok(())` if the chain is valid, `Err` otherwise.
pub fn validate_cert_chain(
    leaf_der: &[u8],
    additional_certs: &[Vec<u8>],
    config: &CertValidationConfig<'_>,
) -> Result<(), Error> {
    ribergshamra_xml::limits::validate_input_size(leaf_der.len())?;
    if additional_certs.len() > ribergshamra_xml::limits::MAX_SECURITY_ITEMS {
        return Err(Error::Certificate(
            "too many document-supplied certificates".into(),
        ));
    }
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| Error::Certificate(format!("failed to parse leaf certificate: {e}")))?;

    let sig_policy = cert_signature_policy();

    // Build a TrustStore from the trusted certificates
    let mut trust_store = TrustStore::new().with_signature_policy(sig_policy);
    for der in config.trusted_certs {
        trust_store
            .add_der_certificate(der)
            .map_err(|e| Error::Certificate(format!("failed to add trusted cert: {e}")))?;
    }

    if trust_store.is_empty() {
        return Err(Error::Certificate(
            "no trusted certificates available".into(),
        ));
    }

    // Collect all available intermediate certs for chain building:
    // additional certs from XML + untrusted intermediates
    let mut pool: Vec<Certificate> = Vec::new();
    for der in additional_certs {
        if der.as_slice() == leaf_der {
            continue; // skip the leaf itself
        }
        if let Ok(c) = Certificate::from_der(der) {
            pool.push(c);
        }
    }
    for der in config.untrusted_certs {
        if let Ok(c) = Certificate::from_der(der) {
            pool.push(c);
        }
    }

    // Resolve validation time
    let validation_time = if config.skip_time_checks {
        None
    } else {
        Some(resolve_verification_time(config.verification_time)?)
    };

    // Check if the leaf is directly a trusted cert (self-signed trusted)
    let leaf_der_owned = leaf_der.to_vec();
    if trust_store.contains_der(&leaf_der_owned) {
        // Self-signed trusted cert — verify self-signature via ritsp-ltv
        ritsp_ltv::crypto::verify::verify_certificate_signature_with_policy(
            &leaf,
            &leaf,
            &sig_policy,
        )
        .map_err(|e| Error::Certificate(format!("self-signature verification failed: {e}")))?;
        // Check time validity if required
        if let Some(ref time) = validation_time {
            check_cert_time_validity(&leaf, time)?;
        }
        if !config.crls.is_empty() {
            check_crls(
                &leaf,
                &leaf,
                config.crls,
                config.verification_time,
                config.skip_time_checks,
            )?;
        }
        return Ok(());
    }

    // Build an ordered chain from leaf through intermediates. The per-link
    // signature checks honour the same policy the trust store will use, so a
    // weak-but-valid link is not dropped before verify_chain runs.
    let anchor_subjects = trust_anchor_subjects(&trust_store);
    let chain =
        build_chain_from_pool_with_policy(&leaf, &pool, &anchor_subjects, None, &sig_policy)
            .map_err(|e| Error::Certificate(format!("cannot build certificate chain: {e}")))?;

    // Verify the chain against the trust store
    let anchor = trust_store
        .verify_chain(&chain, validation_time)
        .map_err(|e| Error::Certificate(format!("{e}")))?;

    // Check CRLs against the leaf cert
    if !config.crls.is_empty() {
        // Use the leaf's issuer on the path that actually passed validation.
        // A different configured same-key reissue may have failed validity or
        // profile checks and must not replace this issuer's cRLSign policy.
        let issuer = chain.get(1).unwrap_or(anchor);
        check_crls(
            &leaf,
            issuer,
            config.crls,
            config.verification_time,
            config.skip_time_checks,
        )?;
    }

    Ok(())
}

/// Parse a verification time string into a `der::DateTime`.
/// Format: "YYYY-MM-DD+HH:MM:SS"
fn parse_verification_time(s: &str) -> Result<der::DateTime, Error> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() != 19
        || !bytes.is_ascii()
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'+' | b'T')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7 | 10 | 13 | 16) && !byte.is_ascii_digit())
    {
        return Err(Error::Certificate(format!(
            "invalid verification time format: {s}"
        )));
    }

    let year: u16 = s[0..4]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid year in time: {s}")))?;
    let month: u8 = s[5..7]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid month in time: {s}")))?;
    let day: u8 = s[8..10]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid day in time: {s}")))?;

    // Separator can be '+' or 'T'
    let rest = &s[11..];
    let hour: u8 = rest[0..2]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid hour in time: {s}")))?;
    let min: u8 = rest[3..5]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid minute in time: {s}")))?;
    let sec: u8 = rest[6..8]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid second in time: {s}")))?;

    der::DateTime::new(year, month, day, hour, min, sec)
        .map_err(|e| Error::Certificate(format!("invalid verification time: {e}")))
}

/// Get the current time as a `der::DateTime`, or use the override.
fn resolve_verification_time(override_time: Option<&str>) -> Result<der::DateTime, Error> {
    if let Some(time_str) = override_time {
        return parse_verification_time(time_str);
    }

    // Use current system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Certificate(format!("system time error: {e}")))?;

    der::DateTime::from_unix_duration(now)
        .map_err(|e| Error::Certificate(format!("time conversion error: {e}")))
}

/// Convert an x509_cert Time to der::DateTime.
fn x509_time_to_datetime(t: &x509_cert::time::Time) -> Result<der::DateTime, Error> {
    Ok(t.to_date_time())
}

/// Check if a certificate is valid at the given time.
fn check_cert_time_validity(cert: &Certificate, verif_time: &der::DateTime) -> Result<(), Error> {
    let not_before = x509_time_to_datetime(&cert.tbs_certificate.validity.not_before)?;
    let not_after = x509_time_to_datetime(&cert.tbs_certificate.validity.not_after)?;

    if *verif_time < not_before {
        return Err(Error::Certificate(format!(
            "certificate is not yet valid (notBefore: {not_before:?})"
        )));
    }
    if *verif_time > not_after {
        return Err(Error::Certificate(format!(
            "certificate has expired (notAfter: {not_after:?})"
        )));
    }

    Ok(())
}

/// Check leaf certificate against CRLs.
///
/// Only complete CRLs authenticated by the validated certificate's
/// actual issuer can supply revocation status. Configured CRLs require at least
/// one applicable list; unavailable/unsupported evidence fails closed. CRLs
/// must be current unless the caller explicitly skips time validity checks.
fn check_crls(
    leaf: &Certificate,
    issuer: &Certificate,
    crls: &[Vec<u8>],
    verification_time_str: Option<&str>,
    skip_time_checks: bool,
) -> Result<(), Error> {
    use x509_cert::crl::CertificateList;

    let leaf_serial = &leaf.tbs_certificate.serial_number;
    let verif_time = resolve_verification_time(verification_time_str)?;
    if crls.len() > ribergshamra_xml::limits::MAX_SECURITY_ITEMS {
        return Err(Error::Certificate("too many CRLs".into()));
    }
    let mut applicable = false;

    for crl_der in crls {
        ribergshamra_xml::limits::validate_input_size(crl_der.len())?;
        let crl = CertificateList::from_der(crl_der)
            .map_err(|e| Error::Certificate(format!("failed to parse CRL: {e}")))?;

        if crl.tbs_cert_list.issuer != leaf.tbs_certificate.issuer {
            continue;
        }
        validate_complete_crl(&crl, &verif_time, skip_time_checks)?;
        let policy = cert_signature_policy();
        let authenticated = issuer.tbs_certificate.subject == leaf.tbs_certificate.issuer
            && ritsp_ltv::crypto::verify::verify_certificate_signature_with_policy(
                leaf, issuer, &policy,
            )
            .is_ok()
            && authenticate_crl(&crl, issuer, &policy).is_ok();
        if !authenticated {
            return Err(Error::Certificate(
                "CRL is not authenticated by the certificate issuer".into(),
            ));
        }
        applicable = true;

        // Check if the leaf cert's serial is in the revoked list
        if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            for revoked in revoked_certs {
                if revoked.serial_number == *leaf_serial {
                    // Check revocation date against verification time
                    let revocation_time = x509_time_to_datetime(&revoked.revocation_date)?;
                    if verif_time >= revocation_time {
                        return Err(Error::Certificate(
                            "certificate has been revoked (found in CRL)".into(),
                        ));
                    }
                    // Revocation date is after verification time — cert wasn't revoked yet
                }
            }
        }
    }
    if !applicable {
        return Err(Error::Certificate("no applicable authenticated CRL".into()));
    }
    Ok(())
}

fn validate_complete_crl(
    crl: &x509_cert::crl::CertificateList,
    now: &der::DateTime,
    skip_time_checks: bool,
) -> Result<(), Error> {
    // x509-cert's TbsCertList decoder currently requires an explicit version.
    // Only v2 (1) is valid when present; v1/v3 encodings must not be accepted.
    if crl.tbs_cert_list.version != x509_cert::Version::V2 {
        return Err(Error::Certificate("explicit CRL version must be v2".into()));
    }
    if crl.signature_algorithm != crl.tbs_cert_list.signature || crl.signature.unused_bits() != 0 {
        return Err(Error::Certificate(
            "inconsistent CRL signature encoding".into(),
        ));
    }
    let this_update = crl.tbs_cert_list.this_update.to_date_time();
    let next_update = crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .ok_or_else(|| Error::Certificate("CRL lacks nextUpdate".into()))?
        .to_date_time();
    if next_update <= this_update
        || (!skip_time_checks && (this_update > *now || next_update <= *now))
    {
        return Err(Error::Certificate(
            "CRL is outside its validity window".into(),
        ));
    }
    let validate_extensions = |extensions: &x509_cert::ext::Extensions, entry: bool| {
        let mut seen = std::collections::HashSet::new();
        for extension in extensions {
            let oid = extension.extn_id.to_string();
            if !seen.insert(extension.extn_id)
                || extension.critical
                || matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28" | "2.5.29.29")
            {
                return Err(Error::Certificate(
                    "unsupported/duplicate CRL extension (complete direct CRLs required)".into(),
                ));
            }
            if entry && oid == "2.5.29.21" {
                let reason =
                    x509_cert::ext::pkix::CrlReason::from_der(extension.extn_value.as_bytes())
                        .map_err(|error| {
                            Error::Certificate(format!("CRL entry reason: {error}"))
                        })?;
                if reason == x509_cert::ext::pkix::CrlReason::RemoveFromCRL {
                    return Err(Error::Certificate(
                        "removeFromCRL requires unsupported delta CRL processing".into(),
                    ));
                }
            }
        }
        Ok(())
    };
    if let Some(extensions) = &crl.tbs_cert_list.crl_extensions {
        validate_extensions(extensions, false)?;
    }
    if let Some(entries) = &crl.tbs_cert_list.revoked_certificates {
        if entries.len() > ribergshamra_xml::limits::MAX_NODES {
            return Err(Error::Certificate("too many CRL entries".into()));
        }
        for entry in entries {
            if let Some(extensions) = &entry.crl_entry_extensions {
                validate_extensions(extensions, true)?;
            }
        }
    }
    Ok(())
}

fn authenticate_crl(
    crl: &x509_cert::crl::CertificateList,
    issuer: &Certificate,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    validate_crl_signing_key_usage(issuer)?;
    let tbs = crl
        .tbs_cert_list
        .to_der()
        .map_err(|error| Error::Certificate(error.to_string()))?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| Error::Certificate(error.to_string()))?;
    ritsp_ltv::crypto::verify::verify_signature_by_algid_with_policy(
        &tbs,
        crl.signature.raw_bytes(),
        &spki,
        &crl.signature_algorithm,
        policy,
    )
    .map_err(|error| Error::Certificate(format!("CRL signature: {error}")))
}

/// Feature-independent strict KeyUsage check: the dependency's flag decoder
/// masks unused bits, and the shared LTV parser is not enabled by this facade.
fn validate_crl_signing_key_usage(issuer: &Certificate) -> Result<(), Error> {
    let oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");
    let mut extensions = issuer
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.extn_id == oid);
    let Some(extension) = extensions.next() else {
        return Ok(());
    };
    if extensions.next().is_some() {
        return Err(Error::Certificate(
            "CRL issuer has duplicate keyUsage".into(),
        ));
    }
    let bits = der::asn1::BitString::from_der(extension.extn_value.as_bytes())
        .map_err(|error| Error::Certificate(format!("CRL issuer keyUsage: {error}")))?;
    let bytes = bits.raw_bytes();
    if bytes.is_empty()
        || bytes.iter().all(|byte| *byte == 0)
        || (bits.unused_bits() > 0
            && bytes.last().unwrap() & ((1u8 << bits.unused_bits()) - 1) != 0)
    {
        return Err(Error::Certificate(
            "CRL issuer has malformed keyUsage bits".into(),
        ));
    }
    if bytes[0] & 0x02 == 0 {
        return Err(Error::Certificate(
            "issuer keyUsage does not permit CRL signing".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: &str = "2026-06-01T12:00:00";

    fn time(value: &str) -> x509_cert::time::Time {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_date_time(parse_verification_time(value).unwrap()).unwrap(),
        )
    }

    fn signature_algorithm() -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(der::Any::from_der(&[0x05, 0x00]).unwrap()),
        }
    }

    // Committed interoperability key, used only to sign ordinary bounded test
    // certificates/CRLs. No fixture files or algorithms are changed.
    fn sign(bytes: &[u8]) -> der::asn1::BitString {
        let key = crate::loader::load_rsa_private_pem(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .unwrap()
        .to_signing_key()
        .unwrap()
        .unwrap();
        let signature =
            ribergshamra_crypto::sign::from_uri(ribergshamra_core::algorithm::RSA_SHA256)
                .unwrap()
                .sign(&key, bytes)
                .unwrap();
        der::asn1::BitString::from_bytes(&signature).unwrap()
    }

    fn extension(oid: &str, critical: bool, value: &[u8]) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: oid.parse().unwrap(),
            critical,
            extn_value: der::asn1::OctetString::new(value).unwrap(),
        }
    }

    fn resign_cert(mut cert: Certificate) -> Certificate {
        cert.signature_algorithm = signature_algorithm();
        cert.tbs_certificate.signature = signature_algorithm();
        cert.signature = sign(&cert.tbs_certificate.to_der().unwrap());
        cert
    }

    fn issuer_and_leaf() -> (Certificate, Certificate) {
        let mut issuer = Certificate::from_der(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-cert.der"
        ))
        .unwrap();
        issuer.tbs_certificate.subject = "CN=CRL Regression Issuer".parse().unwrap();
        issuer.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
        issuer.tbs_certificate.validity = x509_cert::time::Validity {
            not_before: time("2025-01-01T00:00:00"),
            not_after: time("2027-01-01T00:00:00"),
        };
        issuer.tbs_certificate.extensions = Some(vec![
            extension("2.5.29.19", true, &[0x30, 0x03, 0x01, 0x01, 0xff]),
            extension("2.5.29.15", true, &[0x03, 0x02, 0x01, 0x06]),
        ]);
        let issuer = resign_cert(issuer);
        let mut leaf = issuer.clone();
        leaf.tbs_certificate.subject = "CN=CRL Regression Leaf".parse().unwrap();
        leaf.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[7]).unwrap();
        leaf.tbs_certificate.extensions = Some(vec![
            extension("2.5.29.19", true, &[0x30, 0]),
            extension("2.5.29.15", true, &[0x03, 0x02, 0x07, 0x80]),
        ]);
        (issuer, resign_cert(leaf))
    }

    fn resign_crl(mut crl: x509_cert::crl::CertificateList) -> x509_cert::crl::CertificateList {
        crl.signature_algorithm = signature_algorithm();
        crl.tbs_cert_list.signature = signature_algorithm();
        crl.signature = sign(&crl.tbs_cert_list.to_der().unwrap());
        crl
    }

    fn crl(issuer: &Certificate) -> x509_cert::crl::CertificateList {
        resign_crl(x509_cert::crl::CertificateList {
            tbs_cert_list: x509_cert::crl::TbsCertList {
                version: x509_cert::Version::V2,
                signature: signature_algorithm(),
                issuer: issuer.tbs_certificate.subject.clone(),
                this_update: time("2026-06-01T11:00:00"),
                next_update: Some(time("2026-06-01T13:00:00")),
                revoked_certificates: None,
                crl_extensions: None,
            },
            signature_algorithm: signature_algorithm(),
            signature: der::asn1::BitString::from_bytes(&[]).unwrap(),
        })
    }

    fn validate(
        issuer: &Certificate,
        leaf: &Certificate,
        crls: &[Vec<u8>],
        skip_time_checks: bool,
    ) -> Result<(), Error> {
        validate_cert_chain(
            &leaf.to_der().unwrap(),
            &[],
            &CertValidationConfig {
                trusted_certs: &[issuer.to_der().unwrap()],
                untrusted_certs: &[],
                crls,
                verification_time: Some(AT),
                skip_time_checks,
            },
        )
    }

    #[test]
    fn authenticated_current_complete_crl_accepts_and_revocation_date_applies() {
        let (issuer, leaf) = issuer_and_leaf();
        let mut list = crl(&issuer);
        validate(&issuer, &leaf, &[list.to_der().unwrap()], false).unwrap();
        for (date, accepted) in [
            ("2026-06-01T11:30:00", false),
            ("2026-06-01T12:30:00", true),
        ] {
            list.tbs_cert_list.revoked_certificates = Some(vec![x509_cert::crl::RevokedCert {
                serial_number: leaf.tbs_certificate.serial_number.clone(),
                revocation_date: time(date),
                crl_entry_extensions: None,
            }]);
            let signed = resign_crl(list.clone());
            assert_eq!(
                validate(&issuer, &leaf, &[signed.to_der().unwrap()], false).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn crl_authentication_and_applicability_are_required_even_when_time_checks_skip() {
        let (issuer, leaf) = issuer_and_leaf();
        let mut list = crl(&issuer);
        // The signed dates cannot be changed without authenticating the CRL.
        list.tbs_cert_list.this_update = time("2026-06-01T10:00:00");
        for skip in [false, true] {
            assert!(validate(&issuer, &leaf, &[list.to_der().unwrap()], skip).is_err());
        }
        list.tbs_cert_list.issuer = "CN=Unrelated CRL Issuer".parse().unwrap();
        let list = resign_crl(list);
        assert!(validate(&issuer, &leaf, &[list.to_der().unwrap()], false).is_err());
    }

    #[test]
    fn crl_freshness_is_default_and_explicit_skip_is_preserved() {
        let (issuer, leaf) = issuer_and_leaf();
        for (this_update, next_update) in [
            ("2026-06-01T13:00:00", "2026-06-01T14:00:00"),
            ("2026-06-01T10:00:00", AT),
        ] {
            let mut list = crl(&issuer);
            list.tbs_cert_list.this_update = time(this_update);
            list.tbs_cert_list.next_update = Some(time(next_update));
            let list = resign_crl(list).to_der().unwrap();
            assert!(validate(&issuer, &leaf, std::slice::from_ref(&list), false).is_err());
            validate(&issuer, &leaf, &[list], true).unwrap();
        }
        let mut list = crl(&issuer);
        list.tbs_cert_list.next_update = None;
        assert!(validate(&issuer, &leaf, &[resign_crl(list).to_der().unwrap()], true).is_err());
    }

    #[test]
    fn complete_crl_rejects_unsupported_versions_scope_and_entry_semantics() {
        let (issuer, leaf) = issuer_and_leaf();
        let now = parse_verification_time(AT).unwrap();
        let mut list = crl(&issuer);
        list.signature_algorithm.oid =
            der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
        assert!(validate_complete_crl(&list, &now, false).is_err());
        let mut list = crl(&issuer);
        list.signature = der::asn1::BitString::new(1, list.signature.raw_bytes()).unwrap();
        assert!(validate_complete_crl(&list, &now, false).is_err());
        for version in [x509_cert::Version::V1, x509_cert::Version::V3] {
            let mut list = crl(&issuer);
            list.tbs_cert_list.version = version;
            assert!(validate_complete_crl(&list, &now, false).is_err());
        }
        for ext in [
            extension("2.5.29.27", false, &[0x02, 1, 1]),
            extension("2.5.29.28", false, &[0x30, 0]),
            extension("2.5.29.29", false, &[0x30, 0]),
            extension("1.2.3.4", true, &[0x05, 0]),
        ] {
            let mut list = crl(&issuer);
            list.tbs_cert_list.crl_extensions = Some(vec![ext]);
            assert!(validate_complete_crl(&list, &now, false).is_err());
        }
        let mut list = crl(&issuer);
        let reason = extension("2.5.29.21", false, &[0x0a, 1, 8]);
        list.tbs_cert_list.revoked_certificates = Some(vec![x509_cert::crl::RevokedCert {
            serial_number: leaf.tbs_certificate.serial_number.clone(),
            revocation_date: time("2026-06-01T11:30:00"),
            crl_entry_extensions: Some(vec![reason]),
        }]);
        assert!(validate_complete_crl(&list, &now, false).is_err());
        list.tbs_cert_list.revoked_certificates = None;
        let ext = extension("2.5.29.20", false, &[0x02, 1, 1]);
        list.tbs_cert_list.crl_extensions = Some(vec![ext.clone(), ext]);
        assert!(validate_complete_crl(&list, &now, false).is_err());
    }

    #[test]
    fn crl_issuer_key_usage_is_optional_but_strict_when_present() {
        let (mut issuer, _) = issuer_and_leaf();
        issuer.tbs_certificate.extensions = None;
        validate_crl_signing_key_usage(&issuer).unwrap();
        for encoded in [&[0x03, 0x02, 0x01, 0x06][..], &[0x03, 0x02, 0x00, 0x06]] {
            issuer.tbs_certificate.extensions = Some(vec![extension("2.5.29.15", true, encoded)]);
            validate_crl_signing_key_usage(&issuer).unwrap();
        }
        for encoded in [
            &[0x03, 0x02, 0x02, 0x04][..], // keyCertSign only
            &[0x03, 0x02, 0x02, 0x06],     // cRLSign is marked unused
            &[0x03, 0x02, 0x00, 0x00],     // empty usage
            &[0x03, 0x01, 0x00],           // no content octet
            &[0x03, 0x02, 0x00, 0x06, 0],  // trailing data
        ] {
            issuer.tbs_certificate.extensions = Some(vec![extension("2.5.29.15", true, encoded)]);
            assert!(validate_crl_signing_key_usage(&issuer).is_err());
        }
        let ext = extension("2.5.29.15", true, &[0x03, 0x02, 0x01, 0x06]);
        issuer.tbs_certificate.extensions = Some(vec![ext.clone(), ext]);
        assert!(validate_crl_signing_key_usage(&issuer).is_err());
    }

    #[test]
    fn crl_uses_actual_validated_anchor_key_usage() {
        let (mut issuer, leaf) = issuer_and_leaf();
        issuer.tbs_certificate.extensions.as_mut().unwrap()[1] =
            extension("2.5.29.15", true, &[0x03, 0x02, 0x02, 0x04]);
        let issuer = resign_cert(issuer);
        let mut other = issuer.clone();
        other.tbs_certificate.validity.not_after = time("2026-01-01T00:00:00");
        other.tbs_certificate.extensions.as_mut().unwrap()[1] =
            extension("2.5.29.15", true, &[0x03, 0x02, 0x01, 0x06]);
        let other = resign_cert(other);
        let trusted = [issuer.to_der().unwrap(), other.to_der().unwrap()];
        let error = validate_cert_chain(
            &leaf.to_der().unwrap(),
            &[],
            &CertValidationConfig {
                trusted_certs: &trusted,
                untrusted_certs: &[],
                crls: &[crl(&issuer).to_der().unwrap()],
                verification_time: Some(AT),
                skip_time_checks: false,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("CRL is not authenticated by the certificate issuer"),
            "{error}"
        );
    }

    #[test]
    fn directly_trusted_self_signed_certificate_still_checks_crls() {
        let (issuer, _) = issuer_and_leaf();
        let mut list = crl(&issuer);
        validate(&issuer, &issuer, &[list.to_der().unwrap()], false).unwrap();
        list.tbs_cert_list.revoked_certificates = Some(vec![x509_cert::crl::RevokedCert {
            serial_number: issuer.tbs_certificate.serial_number.clone(),
            revocation_date: time("2026-06-01T11:30:00"),
            crl_entry_extensions: None,
        }]);
        assert!(validate(
            &issuer,
            &issuer,
            &[resign_crl(list).to_der().unwrap()],
            false
        )
        .is_err());
    }

    #[test]
    fn verification_time_accepts_documented_separators() {
        let expected = der::DateTime::new(2025, 12, 10, 1, 2, 3).unwrap();
        assert_eq!(
            parse_verification_time("2025-12-10+01:02:03").unwrap(),
            expected
        );
        assert_eq!(
            parse_verification_time(" 2025-12-10T01:02:03 ").unwrap(),
            expected
        );
    }

    #[test]
    fn verification_time_rejects_malformed_settings() {
        for setting in [
            "2025-12-10+01:02",
            "2025/12/10+01:02:03",
            "2025-12-10 01:02:03",
            "2025-12-10+01-02-03",
            "2025-12-10+01:02:03 trailing",
            "2025-13-10+01:02:03",
            "2025-12-10+25:02:03",
            "202é-12-10+01:02:03",
            "2025-12-10+01:é2:03",
        ] {
            assert!(
                parse_verification_time(setting).is_err(),
                "setting: {setting}"
            );
        }
    }
}
