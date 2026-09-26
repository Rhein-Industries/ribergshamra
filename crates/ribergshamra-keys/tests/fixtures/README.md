# Packaged interoperability fixtures

These files are byte-for-byte copies of the existing repository `test-data/`
fixtures used by this crate's tests and key-decoding profile example. Keeping them inside the crate
makes tests usable from an extracted crates.io archive. The original repository
fixture tree remains unchanged. These are public test keys and historical
interoperability documents, not production credentials.

Original paths in the repository:

- `test-data/keys/cakey.pem`
- `test-data/keys/keys.xml`
- `test-data/keys/rsa/rsa-2048-key.pem`
- `test-data/keys/rsa/rsa-2048-pubkey.pem`
- `test-data/keys/rsa/rsa-2048-cert.der`
- `test-data/keys/rsa/rsa-2048-key.p12`
- `test-data/keys/ml-dsa/ml-dsa-44-key.p12`
- `test-data/xmlenc11-interop-2012/DH-1024_SHA256WithDSA.p12`
- `test-data/keys/dhx/dhx-rfc5114-3-first-key.pem`
- `test-data/keys/dhx/dhx-rfc5114-3-second-pubkey.pem`
- `test-data/keys/rsa/rsa-2048-key.p8-pem`
- `test-data/keys/rsa/rsa-2048-cert.pem`
- `test-data/keys/ec/ec-prime384v1-cert.pem`
- `test-data/keys/ec/ec-prime256v1-key.p8-pem`
- `test-data/keys/ec/ec-prime256v1-key.pem`
- `test-data/keys/ec/ec-prime384v1-key.p8-pem`
- `test-data/keys/ec/ec-prime384v1-key.pem`
- `test-data/keys/ec/ec-prime521v1-key.p8-pem`
- `test-data/keys/ec/ec-prime521v1-key.pem`
- `test-data/keys/dsa/dsa-2048-key.p8-pem`
- `test-data/keys/dsa/dsa-2048-key.pem`

The XMLSec key fixtures and their passwords are documented in the repository
`test-data/keys/README.md`.
