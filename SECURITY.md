# Security policy

ribergshamra is Rhein Industries' maintained fork of
[bergshamra](https://github.com/kushaldas/bergshamra). Security problems in
ribergshamra are handled by Rhein Industries. Please do not send ribergshamra
reports to the bergshamra author.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

<https://github.com/Rhein-Industries/ribergshamra/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Please include the affected crate and version or commit, the
enabled features (document provider, `fips`, `legacy-algorithms`,
`post-quantum`, `pkcs11`), and a description of the impact with, if possible,
a minimal reproduction such as a signed or encrypted XML document.

We acknowledge reports as soon as we can and agree on a disclosure timeline
with the reporter. Fixes are released as a patch release and announced
through a GitHub security advisory. If the problem also affects upstream
bergshamra, we notify its author privately before any public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 0.10.x (latest) | Yes |
| < 0.10 | No (bergshamra releases; see upstream) |

Cryptographic operations are provided by
[riptering](https://github.com/Rhein-Industries/riptering) and trust-store and
certificate-chain validation by
[ritsp-ltv](https://github.com/Rhein-Industries/ritsp-ltv); see their security
policies for provider-level and validation-infrastructure issues.
