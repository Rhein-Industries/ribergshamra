# Packaged interoperability fixtures

These files are byte-for-byte copies of the existing repository `test-data/`
fixtures used by this crate's tests. Keeping them inside the crate
makes tests usable from an extracted crates.io archive. The original repository
fixture tree remains unchanged. These are public test keys and historical
interoperability documents, not production credentials.

Original paths in the repository:

- `test-data/keys/rsa/rsa-2048-key.p12`
- `test-data/keys/rsa/rsa-4096-key.p12`
- `test-data/keys/ec/ec-prime256v1-key.p12`

The XMLSec key fixtures and their passwords are documented in the repository
`test-data/keys/README.md`.
