# Contributing to ribergshamra

ribergshamra is Rhein Industries' maintained fork of
[bergshamra](https://github.com/kushaldas/bergshamra). Issues and pull
requests are welcome at <https://github.com/Rhein-Industries/ribergshamra>.
Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License of contributions

ribergshamra is licensed under BSD-2-Clause (see [LICENSE](LICENSE)). By
submitting a contribution you agree that it is licensed under the same terms.
No contributor license agreement and no DCO sign-off are required.

## Checks

CI (`.github/workflows/ci.yml`) runs rustfmt, clippy and the unit tests for
the default, RustCrypto and AWS-LC feature sets, the Rust 1.88 MSRV check, the
xmlsec interoperability gate (`tests/run-provider-interop.sh`), the SoftHSM2
token tests and the AWS-LC FIPS build on GitHub-hosted runners. Pull requests
must pass it; `--all-features` is intentionally invalid because the document
providers are mutually exclusive.

XML-DSig/XML-Enc algorithm URIs, XML namespaces and the files under
`test-data/` and `specs/` are shared with the W3C and xmlsec test suites; do
not change them to make a test pass.

## Releases

Publishing to crates.io is manual for now and done by the maintainers in the
`crates-maintainers` team, crate by crate in dependency order:
`ribergshamra-core`, `ribergshamra-xml`, `ribergshamra-crypto`,
`ribergshamra-pkcs12`, `ribergshamra-c14n`, `ribergshamra-keys`,
`ribergshamra-transforms`, `ribergshamra-dsig`, `ribergshamra-enc`,
`ribergshamra`.
