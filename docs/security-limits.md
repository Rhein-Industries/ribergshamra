# Security processing limits

XML security entrypoints use the shared `ribergshamra_xml::limits` policy before
signature, transform, encryption, or canonicalization work. Public DOM entrypoints
check caller-built documents too. These are fixed defaults, and accepting a
document in an earlier version does not guarantee it remains within this policy.

| Resource | Limit |
|---|---:|
| Source XML, binary transform input, detached regular file | 16 MiB |
| Expanded DOM content, serialized/canonical/transform output | 32 MiB |
| Document nodes | 100,000 |
| Element depth | 128 |
| Attributes plus namespace declarations on one element | 128 |
| Signatures, references, embedded certificates | 64 each per document |
| XPath/XPointer expression | 16 KiB |
| XPath expression recursion | 64 |
| Transform chain | 32 |
| XSLT recursion | 128 |
| Estimated XML work; XSLT execution work | 10,000,000 units each |

A borrowed streaming preflight bounds lexical node/depth/attribute counts before
Uppsala constructs its DOM. Uppsala retains its entity expansion limits; expanded
DOM content is checked afterward. The DOM byte budget includes qualified names,
namespace strings, attributes, text, comments, and document metadata. XML work
uses a conservative product of node count and reference/transform/expression
cost. This bounds supported work shapes, not elapsed time or every allocation.

Serialization streams into a bounded writer. Canonicalization caps output before
forwarding bytes and stops at node/namespace/attribute boundaries on overflow.
XSLT shares recursion/work/output accounting across the whole execution and
checks output space before appending escaped text. A transform's output is also
checked before the next stage; XML re-parsing still uses the 16 MiB input cap.

Detached files require an explicit base directory or URI mapping. The library
does not search its process working directory. Files must be regular and reads
are bounded even when a file grows after its metadata check. URI authorization is
an application policy: configuring a directory authorizes its contained files.
On Unix, directory descriptors, no-follow component traversal, descriptor-relative
metadata checks and final-handle validation preserve the containment decision
while opening. Other platforms retain canonical path checks and require lookup
directories to be protected from concurrent untrusted changes. Exact mappings
authorize the caller-selected resolved file. Mapped or authorized files can
therefore be processed before signature validity is established; applications should grant only the resources they intend to use.

Configured CRLs require applicable issuer-authenticated evidence. Normal policy
checks freshness, inner/outer signature algorithms, CRL-signing key usage, and
the complete/direct CRL profile. Delta, indirect, scoped, critical unsupported,
duplicate, and removeFromCRL forms fail closed. This implements leaf checking,
not a complete online revocation engine. Explicit `skip_time_checks` disables
CRL currentness alongside certificate time validity; signature authentication,
supported scope, valid window ordering, and revocation-date evaluation remain.

`X509IssuerSerial` manager selection matches issuer and serial together and fails
if an explicit selector is malformed or unmatched. Supported DN text encodings
compare exact decoded values across UTF8String, PrintableString, and IA5String;
other encodings require exact DER. RDN order and attribute multiplicity remain
significant. This is a narrow selector comparison, not complete internationalized
DN matching. KeyName and inline key material retain their existing alternative
key-selection semantics; signature and trust verification remain mandatory.

Canonical XML 1.1 subset handling now inherits only `xml:lang`/`xml:space`, and
joins `xml:base` across contiguous omitted ancestors using its modified URI
resolution rules. Exclusive C14N honors excluded attributes. Canonical bytes
change for documents affected by these corrected cases; re-signing or migration
may be necessary for signatures produced using the old behavior.

## RustCrypto RSA decryption

RustCrypto software RSA decryption refuses by default, including when the
ordinary `legacy-algorithms` feature is enabled. RSA public-key encryption and
signing retain their separate policies. AWS-LC and explicitly configured HSM
paths retain their provider policy; there is no automatic provider fallback.

The separate `legacy-rsa-decryption` Cargo feature opts into the unpatched
RustCrypto decryption path for compatibility. It forwards through all XML crates
to riptering. This restores functionality; it does not fix the dependency's
timing advisory. The historical XMLSEC gate explicitly enables this feature and
excludes the upstream profile's future-CRL acceptance case. Default-policy
refusal, authentication/currentness and provider behavior have separate tests.

The 0.11 release line requires published riptering 0.7 and ritsp-ltv 0.6.
Update these dependencies together when using their re-exported types directly,
and refresh consumer lockfiles. CI verifies the published registry graph without
local source overrides. Applications upgrading from 0.10 should review these
processing limits, corrected canonical bytes, CRL profile restrictions and the
separate RSA decryption opt-in before deployment.
