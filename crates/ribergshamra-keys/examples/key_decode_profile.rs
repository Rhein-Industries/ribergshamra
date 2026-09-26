//! Local profile of key decoding using the repository's public interop fixtures.
//!
//! Run from the workspace root with the RustCrypto provider and legacy support:
//! `cargo run --release -p ribergshamra-keys --example key_decode_profile -- 20 5`
//! Arguments are imports per sample and number of samples. File I/O and the
//! initial XML parse are outside the timed sections.

use ribergshamra_keys::{keyinfo::resolve_key_info, loader, KeysManager};
use std::{hint::black_box, time::Instant};

fn sample(label: &str, iterations: usize, samples: usize, mut operation: impl FnMut()) {
    operation();
    for sample_index in 0..samples {
        let started = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        println!(
            "{label} sample={} iterations={iterations} ns_per_operation={:.0}",
            sample_index + 1,
            started.elapsed().as_nanos() as f64 / iterations as f64
        );
    }
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let iterations = arguments
        .next()
        .map(|value| value.parse::<usize>().expect("integer iterations"))
        .unwrap_or(20);
    let samples = arguments
        .next()
        .map(|value| value.parse::<usize>().expect("integer samples"))
        .unwrap_or(5);
    assert!(iterations > 0 && samples > 0);

    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys");
    for (label, path) in [
        ("encrypted_rsa2048", "rsa/rsa-2048-key.p8-pem"),
        ("encrypted_p384", "ec/ec-prime384v1-key.p8-pem"),
        ("encrypted_dsa2048", "dsa/dsa-2048-key.p8-pem"),
    ] {
        let pem = zeroize::Zeroizing::new(std::fs::read(fixtures.join(path)).expect("fixture PEM"));
        sample(label, iterations, samples, || {
            let key = loader::load_pem_auto(black_box(pem.as_slice()), Some("secret123"))
                .expect("import public interop fixture");
            assert!(key.has_private_key());
            black_box(key);
        });
    }

    // Certificate imports include PEM, certificate DER, and SPKI decoding.
    // They do not include trust-chain or certificate-signature validation.
    for (label, path) in [
        ("certificate_rsa2048", "rsa/rsa-2048-cert.pem"),
        ("certificate_p384", "ec/ec-prime384v1-cert.pem"),
    ] {
        let pem = std::fs::read(fixtures.join(path)).expect("public certificate fixture");
        sample(label, iterations, samples, || {
            black_box(
                loader::load_x509_cert_pem(black_box(pem.as_slice()))
                    .expect("import public certificate fixture"),
            );
        });
    }

    let rsa = loader::load_rsa_public_pem(
        &std::fs::read(fixtures.join("rsa/rsa-2048-pubkey.pem")).expect("fixture public key"),
    )
    .expect("RSA fixture");
    let xml = format!(
        "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyValue>{}</ds:KeyValue></ds:KeyInfo>",
        rsa.to_key_value_xml("ds").unwrap()
    );
    let doc = uppsala::parse(&xml).expect("fixture KeyInfo XML");
    let key_info = doc.document_element().unwrap();
    let mut manager = KeysManager::new();
    manager.add_key(rsa);
    sample(
        "manager_key_with_inline_rsa",
        iterations * 100,
        samples,
        || {
            black_box(resolve_key_info(key_info, &doc, &manager).expect("manager key"));
        },
    );
}
