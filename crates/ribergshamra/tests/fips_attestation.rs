#![cfg(feature = "fips")]

#[test]
fn document_crypto_requires_initialization_then_attests() {
    let error = ribergshamra::crypto::digest::digest(
        ribergshamra::core::algorithm::SHA256,
        b"must fail before initialization",
    )
    .expect_err("FIPS document crypto must not initialize lazily");
    assert!(
        matches!(
            error,
            ribergshamra::core::Error::Crypto(ref message)
                if message.contains("has not been explicitly initialized")
        ),
        "unexpected pre-initialization error: {error:?}"
    );

    let info = ribergshamra::initialize_backend().expect("selected FIPS provider initialization");
    assert_eq!(info.fips, ribergshamra::FipsStatus::Active);

    let digest = ribergshamra::crypto::digest::digest(
        ribergshamra::core::algorithm::SHA256,
        b"approved operation",
    )
    .expect("approved digest after initialization");
    assert_eq!(digest.len(), 32);
}
