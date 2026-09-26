# Published dependency validation

CI resolves the published crypto and long-term-validation dependencies using
minimum versions from the workspace manifest and the committed registry
lockfile. Compilation, tests and documentation commands use `--locked`.
There are no temporary sibling source overrides or review bootstrap steps.

Native Linux, Windows and macOS run complete supported RustCrypto profiles.
Linux also runs complete AWS-LC profiles, historical interoperability with
explicit RSA compatibility opt-in, isolated SoftHSM tests, and focused FIPS
initialization/attestation on x86_64 and ARM. FIPS checks are not an unrestricted
conformance claim. Physical HSM validation remains deployment work; Windows
tests do not close the documented filesystem race under concurrent untrusted
directory mutation.

Published packages contain their BSD license notice and the existing fixtures
used by unit tests. The full historical interoperability corpus and generated
SoftHSM token/configuration state remain repository resources; hardware tests
retain their documented setup prerequisite.

Release from the dependency layer upward: crypto, long-term validation, the
XML workspace in crate dependency order, then SAML. Validate each release
commit on native runners and each archive with Cargo publish dry-run before
manual publication. These workflows do not publish crates or merge PRs.
