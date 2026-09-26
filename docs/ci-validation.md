# Coordinated review validation

The security review spans riptering, ritsp-ltv, ribergshamra and risaml. Draft
PR CI tests immutable sibling commits from `.github/coordinated-stack.json`.
The setup script fetches and verifies those SHAs, applies Cargo path overrides
only on the ephemeral runner, explicitly selects the pinned package versions,
and rejects unrelated dependency version changes. Subsequent commands use
`--locked`. Production manifests and the committed registry lockfile remain
unchanged by the setup script.

Native Linux, Windows and macOS run complete supported RustCrypto profiles.
Linux also runs complete AWS-LC profiles, the historical interoperability gate,
isolated SoftHSM tests, and explicit FIPS initialization and attestation on
x86_64 and ARM. The general XML fixtures do not initialize FIPS, so the FIPS
gate uses a full workspace build and dedicated attestation fixtures. It is not
an unrestricted FIPS conformance claim. Physical HSM validation remains
deployment work; Windows tests do not close the documented filesystem race
boundary under concurrent untrusted directory mutation.

Merge and release from the dependency layer upward: riptering, ritsp-ltv, the
ribergshamra workspace in crate dependency order, then risaml. Downstream PRs
must update published minimum dependency versions and registry lockfiles and
remove the temporary CI pins before their final merge. Passing coordinated
source CI does not establish that published or deployed consumers have the
fixes. These workflows do not publish crates or merge PRs.
