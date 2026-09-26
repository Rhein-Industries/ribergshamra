# Packaged interoperability fixtures

These files are byte-for-byte copies of the existing repository `test-data/`
fixtures used by this crate's tests. Keeping them inside the crate
makes tests usable from an extracted crates.io archive. The original repository
fixture tree remains unchanged. These are public test keys and historical
interoperability documents, not production credentials.

Original paths in the repository:

- `test-data/keys/rsa/rsa-2048-cert.der`
- `test-data/keys/cacert.pem`
- `test-data/merlin-xmldsig-twenty-three/certs/ca.pem`
- `test-data/aleksey-xmldsig-01/x509data-test.xml`
- `test-data/signedxml/bbauth-metadata.xml`
- `test-data/signedxml/invalid-signature-changed-content.xml`
- `test-data/signedxml/invalid-signature-non-existing-reference.xml`
- `test-data/signedxml/invalid-signature-signature-value.xml`
- `test-data/signedxml/rootxmlns.crt`
- `test-data/signedxml/rootxmlns.xml`
- `test-data/signedxml/saml-external-ns.xml`
- `test-data/signedxml/signature-with-inclusivenamespaces.xml`
- `test-data/signedxml/valid-saml.xml`
- `test-data/signedxml/wsfed-metadata.xml`

The `signedxml` files originated in the [signedxml](https://github.com/leifj/signedxml)
Go library (`testdata/`), as documented by the original fixture README.
