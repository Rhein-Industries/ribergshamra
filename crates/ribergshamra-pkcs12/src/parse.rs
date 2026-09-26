#![forbid(unsafe_code)]

//! BER parsing of PKCS#12 (PFX) structures (RFC 7292).
//!
//! Uses `yasna::parse_ber` since PKCS#12 files use BER encoding, not strict DER.

use ribergshamra_core::Error;
use yasna::models::ObjectIdentifier;
use yasna::{ASN1Error, ASN1ErrorKind, BERReader, Tag};
use zeroize::Zeroizing;

use crate::kdf;
use crate::{Pkcs12Contents, Pkcs12Limits, PrivateKeyDer};

// ── OID constants ──────────────────────────────────────────────────────────

// Content types (PKCS#7)
const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];

// Bag types (PKCS#12)
const OID_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
const OID_PKCS8_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const OID_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];

// Certificate type
const OID_X509_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];

// PBE algorithms
const OID_PBE_SHA1_3DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];

// Cipher
const OID_AES_256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];

// Hash / HMAC
const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];

fn oid(components: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(components)
}

// ── Algorithm types ────────────────────────────────────────────────────────

#[derive(Debug)]
enum EncryptionAlgorithm {
    PbeSha1And3Des {
        salt: Vec<u8>,
        iterations: u32,
    },
    Pbes2 {
        pbkdf2_salt: Vec<u8>,
        pbkdf2_iterations: u32,
        pbkdf2_prf: PrfAlgorithm,
        aes_iv: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy)]
enum PrfAlgorithm {
    HmacSha1,
    HmacSha256,
}

#[derive(Debug, Clone, Copy)]
enum MacHashAlgorithm {
    Sha1,
    Sha256,
}

// ── Parsed structures ──────────────────────────────────────────────────────

struct MacData {
    digest_algorithm: MacHashAlgorithm,
    digest_value: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
}

enum SafeBag {
    KeyBag {
        pkcs8_der: PrivateKeyDer,
    },
    ShroudedKeyBag {
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    },
    CertBag {
        cert_der: Vec<u8>,
    },
    Other,
}

// ── Top-level parser ───────────────────────────────────────────────────────

#[cfg(test)]
fn parse_pfx(data: &[u8], password: &str) -> Result<Pkcs12Contents, Error> {
    parse_pfx_with_limits(data, password, &Pkcs12Limits::default())
}

pub fn parse_pfx_with_limits(
    data: &[u8],
    password: &str,
    limits: &Pkcs12Limits,
) -> Result<Pkcs12Contents, Error> {
    if data.len() > limits.max_input_len {
        return Err(Error::Key(
            "PKCS#12 input exceeds configured size limit".into(),
        ));
    }
    if password.len() > limits.max_password_len {
        return Err(Error::Key(
            "PKCS#12 password exceeds configured size limit".into(),
        ));
    }
    let mut kdf_work = 0;
    let (auth_safe_data, mac_data) = yasna::parse_ber(data, |r| {
        r.read_sequence(|r| {
            // version
            let version = r.next().read_u32()?;
            if version != 3 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }

            // authSafe ContentInfo
            let auth_safe_data = parse_content_info_data(r.next())?;

            // optional macData
            let mac_data = r.read_optional(parse_mac_data)?;

            Ok((auth_safe_data, mac_data))
        })
    })
    .map_err(|e| Error::Key(format!("failed to parse PKCS#12 PFX: {e}")))?;

    // The authenticated safe can contain plaintext private-key bags. Retain
    // it in a zeroizing buffer while parsing so no temporary container copy
    // survives after import.
    // Verify MAC if present
    if let Some(ref mac) = mac_data {
        check_kdf_budget(limits, &mut kdf_work, &mac.salt, mac.iterations, 1)?;
        verify_mac(mac, &auth_safe_data, password)?;
    }

    // Parse the authSafe contents (SEQUENCE OF ContentInfo)
    let content_infos = yasna::parse_ber(&auth_safe_data, |r| {
        let mut content_infos = Vec::new();
        r.read_sequence_of(|r| {
            // `read_sequence_of` also calls this closure at the end marker.
            // Check that an entry exists before charging its count.
            if r.lookahead_tag()? != yasna::tags::TAG_SEQUENCE {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            if content_infos.len() >= limits.max_content_infos {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            content_infos.push(parse_content_info_inner(r)?);
            Ok(())
        })?;
        Ok(content_infos)
    })
    .map_err(|e| Error::Key(format!("failed to parse authSafe contents: {e}")))?;

    // Process each ContentInfo to extract bags
    let mut private_keys = Vec::new();
    let mut certificates = Vec::new();
    let mut bag_count = 0;

    for ci in content_infos {
        let bags_data = match ci {
            ContentInfoInner::Data(data) => data,
            ContentInfoInner::EncryptedData {
                algorithm,
                ciphertext,
            } => Zeroizing::new(decrypt_data(
                &algorithm,
                &ciphertext,
                password,
                limits,
                &mut kdf_work,
            )?),
        };

        // Parse SafeBags from the decrypted data
        let bags = yasna::parse_ber(&bags_data, |r| {
            let mut bags = Vec::new();
            r.read_sequence_of(|r| {
                if r.lookahead_tag()? != yasna::tags::TAG_SEQUENCE {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                if bag_count >= limits.max_bags {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                bag_count += 1;
                bags.push(parse_safe_bag(r)?);
                Ok(())
            })?;
            Ok(bags)
        })
        .map_err(|e| Error::Key(format!("failed to parse SafeBags: {e}")))?;

        for bag in bags {
            match bag {
                SafeBag::KeyBag { pkcs8_der } => {
                    private_keys.push(pkcs8_der);
                }
                SafeBag::ShroudedKeyBag {
                    algorithm,
                    ciphertext,
                } => {
                    let pkcs8_der =
                        decrypt_data(&algorithm, &ciphertext, password, limits, &mut kdf_work)?;
                    private_keys.push(PrivateKeyDer::new(pkcs8_der));
                }
                SafeBag::CertBag { cert_der } => {
                    certificates.push(cert_der);
                }
                SafeBag::Other => {}
            }
        }
    }

    Ok(Pkcs12Contents {
        private_keys,
        certificates,
    })
}

// ── ContentInfo parsing ────────────────────────────────────────────────────

/// Parse top-level ContentInfo that wraps the authSafe: expects OID = data,
/// extracts the OCTET STRING payload.
fn parse_content_info_data(r: BERReader) -> Result<Zeroizing<Vec<u8>>, ASN1Error> {
    r.read_sequence(|r| {
        let content_type = r.next().read_oid()?;
        if content_type != oid(OID_DATA) {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        // [0] EXPLICIT OCTET STRING
        let data = r
            .next()
            .read_tagged(Tag::context(0), |r| r.read_bytes().map(Zeroizing::new))?;
        Ok(data)
    })
}

enum ContentInfoInner {
    Data(Zeroizing<Vec<u8>>),
    EncryptedData {
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    },
}

/// Parse a ContentInfo inside the authSafe SEQUENCE.
fn parse_content_info_inner(r: BERReader) -> Result<ContentInfoInner, ASN1Error> {
    r.read_sequence(|r| {
        let content_type = r.next().read_oid()?;

        if content_type == oid(OID_DATA) {
            let data = r
                .next()
                .read_tagged(Tag::context(0), |r| r.read_bytes().map(Zeroizing::new))?;
            Ok(ContentInfoInner::Data(data))
        } else if content_type == oid(OID_ENCRYPTED_DATA) {
            // [0] EXPLICIT EncryptedData
            r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    // version
                    let _version = r.next().read_u32()?;
                    // EncryptedContentInfo
                    r.next().read_sequence(|r| {
                        // contentType (should be data)
                        let _ct = r.next().read_oid()?;
                        // contentEncryptionAlgorithm
                        let algorithm = parse_algorithm_identifier(r.next())?;
                        // [0] IMPLICIT encrypted content
                        let ciphertext = r
                            .next()
                            .read_tagged_implicit(Tag::context(0), |r| r.read_bytes())?;
                        Ok(ContentInfoInner::EncryptedData {
                            algorithm,
                            ciphertext,
                        })
                    })
                })
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    })
}

// ── SafeBag parsing ────────────────────────────────────────────────────────

fn parse_safe_bag(r: BERReader) -> Result<SafeBag, ASN1Error> {
    r.read_sequence(|r| {
        let bag_type = r.next().read_oid()?;

        if bag_type == oid(OID_KEY_BAG) {
            // [0] EXPLICIT PrivateKeyInfo (PKCS#8 DER, unencrypted)
            let pkcs8_der = r
                .next()
                .read_tagged(Tag::context(0), |r| r.read_der().map(PrivateKeyDer::new))?;
            // Skip optional attributes
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| {
                            let _ = r.read_der()?;
                            Ok(())
                        })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::KeyBag { pkcs8_der })
        } else if bag_type == oid(OID_PKCS8_SHROUDED_KEY_BAG) {
            // [0] EXPLICIT EncryptedPrivateKeyInfo
            let (algorithm, ciphertext) = r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let algorithm = parse_algorithm_identifier(r.next())?;
                    let ciphertext = r.next().read_bytes()?;
                    Ok((algorithm, ciphertext))
                })
            })?;
            // Skip optional attributes
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    // Read and discard each attribute SEQUENCE
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| {
                            let _ = r.read_der()?;
                            Ok(())
                        })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::ShroudedKeyBag {
                algorithm,
                ciphertext,
            })
        } else if bag_type == oid(OID_CERT_BAG) {
            // [0] EXPLICIT CertBag
            let cert_der = r.next().read_tagged(Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let cert_type = r.next().read_oid()?;
                    if cert_type != oid(OID_X509_CERTIFICATE) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    // [0] EXPLICIT OCTET STRING containing DER-encoded certificate
                    let cert_data = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
                    Ok(cert_data)
                })
            })?;
            // Skip optional attributes
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| {
                            let _ = r.read_der()?;
                            Ok(())
                        })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::CertBag { cert_der })
        } else {
            // Skip unknown bag types: read and discard tag [0] value and optional attrs
            let _value = r
                .next()
                .read_tagged(Tag::context(0), |r| r.read_der().map(Zeroizing::new))?;
            let _attrs = r.read_optional(|r| {
                r.read_set_of(|r| {
                    r.read_sequence(|r| {
                        let _oid = r.next().read_oid()?;
                        r.next().read_set_of(|r| {
                            let _ = r.read_der()?;
                            Ok(())
                        })?;
                        Ok(())
                    })
                })
            })?;
            Ok(SafeBag::Other)
        }
    })
}

// ── AlgorithmIdentifier parsing ────────────────────────────────────────────

fn parse_algorithm_identifier(r: BERReader) -> Result<EncryptionAlgorithm, ASN1Error> {
    r.read_sequence(|r| {
        let alg_oid = r.next().read_oid()?;

        if alg_oid == oid(OID_PBE_SHA1_3DES) {
            // Legacy PBE params: SEQUENCE { salt OCTET STRING, iterations INTEGER }
            r.next().read_sequence(|r| {
                let salt = r.next().read_bytes()?;
                let iterations = r.next().read_u32()?;
                Ok(EncryptionAlgorithm::PbeSha1And3Des { salt, iterations })
            })
        } else if alg_oid == oid(OID_PBES2) {
            // PBES2-params: SEQUENCE { keyDerivationFunc AlgId, encryptionScheme AlgId }
            r.next().read_sequence(|r| {
                // keyDerivationFunc (must be PBKDF2)
                let (pbkdf2_salt, pbkdf2_iterations, pbkdf2_prf) = r.next().read_sequence(|r| {
                    let kdf_oid = r.next().read_oid()?;
                    if kdf_oid != oid(OID_PBKDF2) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    // PBKDF2-params: SEQUENCE { salt, iterationCount, keyLength?, prf? }
                    r.next().read_sequence(|r| {
                        let salt = r.next().read_bytes()?;
                        let iterations = r.next().read_u32()?;

                        // The optional length must agree with AES-256-CBC;
                        // do not silently ignore a contradictory parameter.
                        if let Some(key_length) = r.read_optional(|r| r.read_u32())? {
                            if key_length != 32 {
                                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                            }
                        }
                        let prf = r
                            .read_optional(parse_prf)?
                            .unwrap_or(PrfAlgorithm::HmacSha1);

                        Ok((salt, iterations, prf))
                    })
                })?;

                // encryptionScheme
                let aes_iv = r.next().read_sequence(|r| {
                    let enc_oid = r.next().read_oid()?;
                    if enc_oid != oid(OID_AES_256_CBC) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    let iv = r.next().read_bytes()?;
                    Ok(iv)
                })?;

                Ok(EncryptionAlgorithm::Pbes2 {
                    pbkdf2_salt,
                    pbkdf2_iterations,
                    pbkdf2_prf,
                    aes_iv,
                })
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    })
}

/// Parse a PRF AlgorithmIdentifier.
fn parse_prf(r: BERReader) -> Result<PrfAlgorithm, ASN1Error> {
    r.read_sequence(|r| {
        let prf_oid = r.next().read_oid()?;
        // Read optional NULL parameter
        let _null = r.read_optional(|r| r.read_null())?;
        if prf_oid == oid(OID_HMAC_SHA256) {
            Ok(PrfAlgorithm::HmacSha256)
        } else if prf_oid == oid(OID_HMAC_SHA1) {
            Ok(PrfAlgorithm::HmacSha1)
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    })
}

// ── MAC verification ───────────────────────────────────────────────────────

fn parse_mac_data(r: BERReader) -> Result<MacData, ASN1Error> {
    r.read_sequence(|r| {
        // DigestInfo: SEQUENCE { digestAlgorithm, digest }
        let (digest_algorithm, digest_value) = r.next().read_sequence(|r| {
            let alg = r.next().read_sequence(|r| {
                let hash_oid = r.next().read_oid()?;
                // optional NULL
                let _null = r.read_optional(|r| r.read_null())?;
                if hash_oid == oid(OID_SHA256) {
                    Ok(MacHashAlgorithm::Sha256)
                } else if hash_oid == oid(OID_SHA1) {
                    Ok(MacHashAlgorithm::Sha1)
                } else {
                    Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                }
            })?;
            let digest = r.next().read_bytes()?;
            Ok((alg, digest))
        })?;

        let salt = r.next().read_bytes()?;
        let iterations = r.read_optional(|r| r.read_u32())?.unwrap_or(1);

        Ok(MacData {
            digest_algorithm,
            digest_value,
            salt,
            iterations,
        })
    })
}

fn verify_mac(mac: &MacData, auth_safe_data: &[u8], password: &str) -> Result<(), Error> {
    let computed = match mac.digest_algorithm {
        MacHashAlgorithm::Sha1 => {
            let mac_key = Zeroizing::new(kdf::pkcs12_kdf_sha1(
                kdf::ID_MAC,
                password,
                &mac.salt,
                mac.iterations,
                20,
            )?);
            kdf::compute_hmac(riptering::HashAlgorithm::Sha1, &mac_key, auth_safe_data)?
        }
        MacHashAlgorithm::Sha256 => {
            let mac_key = Zeroizing::new(kdf::pkcs12_kdf_sha256(
                kdf::ID_MAC,
                password,
                &mac.salt,
                mac.iterations,
                32,
            )?);
            kdf::compute_hmac(riptering::HashAlgorithm::Sha256, &mac_key, auth_safe_data)?
        }
    };

    if !riptering::digest::constant_time_eq(&computed, &mac.digest_value) {
        return Err(Error::Key(
            "PKCS#12 MAC verification failed (wrong password?)".into(),
        ));
    }

    Ok(())
}

// ── Decryption dispatch ────────────────────────────────────────────────────

fn decrypt_data(
    algorithm: &EncryptionAlgorithm,
    ciphertext: &[u8],
    password: &str,
    limits: &Pkcs12Limits,
    kdf_work: &mut u64,
) -> Result<Vec<u8>, Error> {
    match algorithm {
        EncryptionAlgorithm::PbeSha1And3Des { salt, iterations } => {
            // SHA-1: two hash blocks for the 24-byte key, one for the IV.
            check_kdf_budget(limits, kdf_work, salt, *iterations, 3)?;
            kdf::decrypt_pbe_sha1_3des(ciphertext, password, salt, *iterations)
        }
        EncryptionAlgorithm::Pbes2 {
            pbkdf2_salt,
            pbkdf2_iterations,
            pbkdf2_prf,
            aes_iv,
        } => {
            let blocks = match pbkdf2_prf {
                PrfAlgorithm::HmacSha1 => 2,
                PrfAlgorithm::HmacSha256 => 1,
            };
            check_kdf_budget(limits, kdf_work, pbkdf2_salt, *pbkdf2_iterations, blocks)?;
            match pbkdf2_prf {
                PrfAlgorithm::HmacSha256 => kdf::decrypt_pbes2_aes256cbc(
                    riptering::HashAlgorithm::Sha256,
                    ciphertext,
                    password,
                    pbkdf2_salt,
                    *pbkdf2_iterations,
                    aes_iv,
                ),
                PrfAlgorithm::HmacSha1 => kdf::decrypt_pbes2_aes256cbc(
                    riptering::HashAlgorithm::Sha1,
                    ciphertext,
                    password,
                    pbkdf2_salt,
                    *pbkdf2_iterations,
                    aes_iv,
                ),
            }
        }
    }
}

fn check_kdf_budget(
    limits: &Pkcs12Limits,
    work: &mut u64,
    salt: &[u8],
    iterations: u32,
    blocks: u64,
) -> Result<(), Error> {
    if salt.len() > limits.max_salt_len {
        return Err(Error::Key(
            "PKCS#12 salt exceeds configured size limit".into(),
        ));
    }
    if iterations == 0 || iterations > limits.max_iterations {
        return Err(Error::Key(
            "PKCS#12 iterations outside configured limit".into(),
        ));
    }
    let next = u64::from(iterations)
        .checked_mul(blocks)
        .and_then(|cost| work.checked_add(cost))
        .filter(|next| *next <= limits.max_kdf_work)
        .ok_or_else(|| Error::Key("PKCS#12 aggregate KDF work exceeds configured limit".into()))?;
    *work = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfx_with_bags(content_count: usize, bag_count: usize) -> Vec<u8> {
        pfx_with_bags_encoding(content_count, bag_count, false)
    }

    fn pfx_with_bags_encoding(content_count: usize, bag_count: usize, indefinite: bool) -> Vec<u8> {
        let mut bags = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                for _ in 0..bag_count {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(&[1, 2, 3, 4]));
                        w.next().write_tagged(Tag::context(0), |w| w.write_null());
                    });
                }
            });
        });
        if indefinite {
            assert!(bags[1] < 128, "synthetic BER fixture uses short DER length");
            bags[1] = 0x80;
            bags.extend_from_slice(&[0, 0]);
        }
        let auth_safe = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                for _ in 0..content_count {
                    w.next().write_sequence(|w| {
                        w.next().write_oid(&oid(OID_DATA));
                        w.next()
                            .write_tagged(Tag::context(0), |w| w.write_bytes(&bags));
                    });
                }
            });
        });
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u32(3);
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(OID_DATA));
                    w.next()
                        .write_tagged(Tag::context(0), |w| w.write_bytes(&auth_safe));
                });
            });
        })
    }

    #[test]
    fn input_and_password_bounds_apply_before_parsing() {
        let limits = Pkcs12Limits {
            max_input_len: 2,
            max_password_len: 2,
            ..Default::default()
        };
        let err = parse_pfx_with_limits(b"abc", "", &limits).unwrap_err();
        assert!(err
            .to_string()
            .contains("input exceeds configured size limit"));
        let err = parse_pfx_with_limits(b"", "abc", &limits).unwrap_err();
        assert!(err
            .to_string()
            .contains("password exceeds configured size limit"));
    }

    #[test]
    fn content_and_aggregate_bag_counts_are_bounded() {
        let limits = Pkcs12Limits {
            max_content_infos: 2,
            max_bags: 2,
            ..Default::default()
        };
        assert!(parse_pfx_with_limits(&pfx_with_bags(2, 1), "", &limits).is_ok());
        assert!(parse_pfx_with_limits(&pfx_with_bags_encoding(2, 1, true), "", &limits).is_ok());
        assert!(parse_pfx_with_limits(&pfx_with_bags(3, 0), "", &limits).is_err());
        assert!(parse_pfx_with_limits(&pfx_with_bags(2, 2), "", &limits).is_err());
    }

    #[test]
    fn kdf_limits_include_salt_iterations_and_aggregate_blocks() {
        let limits = Pkcs12Limits {
            max_salt_len: 4,
            max_iterations: 4,
            max_kdf_work: 12,
            ..Default::default()
        };
        let mut work = 0;
        assert!(check_kdf_budget(&limits, &mut work, b"salt", 4, 3).is_ok());
        assert_eq!(work, 12);
        assert!(check_kdf_budget(&limits, &mut work, b"salt", 1, 1).is_err());
        assert_eq!(work, 12, "rejected requests do not mutate the budget");
        assert!(check_kdf_budget(&limits, &mut 0, b"salts", 1, 1).is_err());
        assert!(check_kdf_budget(&limits, &mut 0, b"salt", 0, 1).is_err());
        assert!(check_kdf_budget(&limits, &mut 0, b"salt", 5, 1).is_err());
    }

    #[test]
    fn encryption_dispatch_checks_work_before_provider_use() {
        let limits = Pkcs12Limits {
            max_kdf_work: 1,
            ..Default::default()
        };
        for algorithm in [
            EncryptionAlgorithm::PbeSha1And3Des {
                salt: b"salt".to_vec(),
                iterations: 1,
            },
            EncryptionAlgorithm::Pbes2 {
                pbkdf2_salt: b"salt".to_vec(),
                pbkdf2_iterations: 1,
                pbkdf2_prf: PrfAlgorithm::HmacSha1,
                aes_iv: vec![0; 16],
            },
        ] {
            let err = decrypt_data(&algorithm, b"", "", &limits, &mut 0).unwrap_err();
            assert!(err.to_string().contains("aggregate KDF work"));
        }
    }

    #[test]
    fn mac_parameters_are_bounded_before_password_work() {
        let data = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u32(3);
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(OID_DATA));
                    w.next()
                        .write_tagged(Tag::context(0), |w| w.write_bytes(&[0x30, 0]));
                });
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(OID_SHA256));
                            w.next().write_null();
                        });
                        w.next().write_bytes(&[0; 32]);
                    });
                    w.next().write_bytes(b"saltsalt");
                    w.next().write_u32(2);
                });
            });
        });
        let limits = Pkcs12Limits {
            max_iterations: 1,
            ..Default::default()
        };
        let err = parse_pfx_with_limits(&data, "synthetic", &limits).unwrap_err();
        assert!(err
            .to_string()
            .contains("iterations outside configured limit"));
        let limits = Pkcs12Limits {
            max_kdf_work: 1,
            ..Default::default()
        };
        let err = parse_pfx_with_limits(&data, "synthetic", &limits).unwrap_err();
        assert!(err.to_string().contains("aggregate KDF work"));
    }

    #[test]
    fn pbes2_declared_key_length_must_match_aes256() {
        let algorithm_der = |key_length| {
            yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_oid(&oid(OID_PBES2));
                    w.next().write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(OID_PBKDF2));
                            w.next().write_sequence(|w| {
                                w.next().write_bytes(b"saltsalt");
                                w.next().write_u32(1);
                                w.next().write_u32(key_length);
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&oid(OID_HMAC_SHA256));
                                    w.next().write_null();
                                });
                            });
                        });
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(OID_AES_256_CBC));
                            w.next().write_bytes(&[0; 16]);
                        });
                    });
                });
            })
        };
        assert!(yasna::parse_ber(&algorithm_der(32), parse_algorithm_identifier).is_ok());
        assert!(yasna::parse_ber(&algorithm_der(31), parse_algorithm_identifier).is_err());
    }

    #[test]
    fn mac_verification_requires_full_digest() {
        let data = b"synthetic authenticated safe";
        let password = "synthetic fixture password";
        let salt = b"salt".to_vec();
        let key =
            Zeroizing::new(kdf::pkcs12_kdf_sha256(kdf::ID_MAC, password, &salt, 1, 32).unwrap());
        let digest = kdf::compute_hmac(riptering::HashAlgorithm::Sha256, &key, data).unwrap();
        let mut mac = MacData {
            digest_algorithm: MacHashAlgorithm::Sha256,
            digest_value: digest,
            salt,
            iterations: 1,
        };
        assert!(verify_mac(&mac, data, password).is_ok());
        mac.digest_value.pop();
        assert!(verify_mac(&mac, data, password).is_err());
        mac.digest_value.clear();
        assert!(verify_mac(&mac, data, password).is_err());
    }

    #[test]
    fn test_parse_rsa_2048_p12() {
        let p12_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/rsa/rsa-2048-key.p12"
        ));
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(contents.private_keys.len(), 1, "expected 1 private key");
        assert!(
            !contents.certificates.is_empty(),
            "expected at least 1 certificate"
        );

        // Verify the private key looks like valid PKCS#8 DER (starts with SEQUENCE tag 0x30)
        assert_eq!(contents.private_keys[0][0], 0x30);
    }

    #[test]
    fn test_parse_ec_p256_p12() {
        let p12_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/ec/ec-prime256v1-key.p12"
        ));
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(contents.private_keys.len(), 1);
        assert!(!contents.certificates.is_empty());
        assert_eq!(contents.private_keys[0][0], 0x30);
    }

    #[test]
    fn test_parse_rsa_4096_p12() {
        let p12_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/rsa/rsa-4096-key.p12"
        ));
        if !p12_path.exists() {
            eprintln!("skipping test: {p12_path:?} not found");
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let contents = parse_pfx(&data, "secret123").expect("parse_pfx should succeed");

        assert_eq!(contents.private_keys.len(), 1);
        assert!(!contents.certificates.is_empty());
    }

    #[test]
    fn test_wrong_password_fails_mac() {
        let p12_path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/rsa/rsa-2048-key.p12"
        ));
        if !p12_path.exists() {
            return;
        }
        let data = std::fs::read(p12_path).unwrap();
        let err = parse_pfx(&data, "wrong_password").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("MAC verification failed"),
            "expected MAC error, got: {msg}"
        );
    }
}
