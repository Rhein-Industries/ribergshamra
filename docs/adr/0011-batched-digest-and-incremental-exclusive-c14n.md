# ADR-0011: Batch Digest Updates and Reuse Exclusive C14N Namespace State

> **Note (ribergshamra fork):** this ADR is a historical record from
> bergshamra, written before Rhein Industries forked the workspace and renamed
> it `ribergshamra` (0.10.0). "Bergshamra" below means the same code base;
> crate names, paths and commands are updated to the `ribergshamra` crates,
> and kryptering / tsp-ltv are now riptering / ritsp-ltv.

**Date:** 2026-09-22
**Status:** Accepted
**Context:** Improving XML-DSig throughput for large SAML aggregates and
per-entity MDQ output without changing canonical bytes or signature semantics

## Problem

ADR-0008 introduced document-native signing and streamed canonical output into
the reference digest. That removed a document-sized canonicalization buffer,
but two costs still dominated signing of large SAML aggregates:

1. `ReferenceDigestSink` forwarded every `C14nSink` write directly through a
   dynamic digest interface. Canonicalization emits many one-byte writes for
   punctuation and escaping, so a large document caused a very high number of
   digest update calls.
2. Exclusive C14N reconstructed the complete in-scope namespace map by walking
   the ancestor chain for every element. It also cloned the rendered namespace
   map for every visible element and allocated temporary rendered strings for
   namespace declarations and attributes.

These costs were especially visible in pyFF's eduGAIN workload, where the same
large aggregate is canonicalized and signed several times. They also affected
the full MDQ pipeline, which signs thousands of individual entity documents.

## Decision

### Batch reference digest updates

`ReferenceDigestSink` owns a 64 KiB staging buffer. Small canonicalization
writes, including `write_byte` calls, are appended to that buffer and sent to
the digest implementation in batches.

The sink preserves canonical byte order with these rules:

- A full buffer is flushed before accepting more bytes.
- A write at least as large as the buffer capacity bypasses the buffer, after
  any older buffered bytes have been flushed.
- Remaining bytes are flushed before the digest is finalized.

The buffer is bounded and does not grow with document size. Streaming into the
digest therefore retains the memory property established by ADR-0008.

### Maintain exclusive C14N namespace state incrementally

Exclusive C14N now carries two mutable maps during its depth-first traversal:

- `inscope_ns` contains the namespace bindings in scope at the current node.
- `rendered_ns` contains the namespace bindings most recently emitted into the
  canonical output.

Entering an element applies only that element's namespace declarations. Each
mutation records the previous binding in an undo log. Leaving the subtree
replays the log in reverse order, restoring the parent's state. The same model
is used when emitted namespace declarations update `rendered_ns`.

Namespace scope is updated for invisible as well as visible elements. Namespace
node visibility filtering is evaluated against the incremental map without
constructing another filtered map for each element.

Namespace declarations and attributes use `write_to` methods that stream their
escaped representation directly to the output sink. The existing owned
`NsDecl` and `Attr` values remain in use for sorting and compatibility, but the
final rendered `String` allocation is avoided.

## Correctness Invariants

The optimization must not change XML canonicalization or XML-DSig semantics:

- Output must be byte-for-byte identical to the previous implementation.
- Namespace declarations on invisible ancestors must still affect visible
  descendants.
- Prefix rebinding and namespace undeclaration must apply only to their
  subtree and must not leak into sibling subtrees.
- Undo logs must be restored in reverse order because a traversal step can
  mutate the same prefix more than once.
- Traversal state must be restored when processing a descendant returns an
  error.
- Namespace node-set visibility and inclusive-prefix behavior must remain
  unchanged.
- Digest batching must preserve byte order across byte writes, small slices,
  buffer boundaries, and direct large writes.

Tests cover byte-equivalent direct rendering, mixed digest writes at buffer
boundaries, prefix rebinding between siblings, and default namespace
undeclaration and restoration.

## Alternatives Considered

### Keep one digest update per C14N write

Rejected. It keeps the sink simple but makes dynamic dispatch and digest update
setup dominate a workload composed of many tiny writes.

### Materialize the complete canonical document before hashing

Rejected. A one-shot digest update would reduce call overhead but reintroduce a
document-sized allocation and undermine the streaming design from ADR-0008.

### Make every C14N producer emit larger chunks

Not selected for this change. Coalescing at the digest sink fixes all current
producers behind one private boundary and preserves the general streaming sink
API. Producers may still emit naturally larger chunks where practical.

### Rebuild and clone namespace maps for every element

Rejected. This was the previous implementation and its repeated ancestor walks
and map copies scale poorly for large or deeply nested documents.

### Cache a complete namespace map for every element

Rejected. It trades repeated computation for document-proportional retained
memory and complicates cache ownership and invalidation.

### Fully borrow attributes and namespace declarations from the DOM

Deferred. ADR-0010 proposes this broader allocation reduction. This decision
implements direct output streaming without changing the owned sorting model,
which captures a measured benefit with a smaller correctness surface. ADR-0010
therefore remains Proposed.

## Measured Consequences

The release candidate was tested on a Debian host with four AMD EPYC 7551
virtual CPUs, 7.8 GiB RAM, and Python 3.14.6. The pyFF benchmark used the same
input and configuration for each comparison, at pyFF revision
`f993a09ace19e3a92d7b6040b9fc3ff5e9a24c0e`. The optimized pybergshamra wheel
had SHA-256 digest
`1fb9f46e55c6d5bb1b67415a7d87d6332748bf04b4205179a5a4b5f40afdd778`.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| Four aggregate signatures, median of 3 | 91.22 s | 38.10 s | 58.2% faster |
| Full four-aggregate job, median of 3 | 100.41 s | 40.57 s | 59.6% faster |
| Full eduGAIN MDQ job, 10,685 entities | 404.92 s | 365.82 s | 9.7% faster |

The comparable lxml full four-aggregate job took 40.66 seconds, putting the
optimized path at parity for that workload. Peak RSS for the four-aggregate
job changed from 3,783,052 KiB to 3,675,492 KiB. The MDQ run stayed effectively
flat at 1,239,372 KiB before and 1,239,436 KiB after.

An attribution run measured the digest buffer alone at 62.86 seconds for the
four-signature phase, down from 91.22 seconds. Adding incremental namespace
state and direct rendering reduced the median to 38.10 seconds.

The optimized MDQ run produced 10,685 entity files and 10,685 hash links.
Independent lxml/PyXMLSecurity validation found every entity schema-valid and
signature-valid, and every hash link resolved. The four aggregate outputs also
passed schema validation and independent signature verification.

The Bergshamra workspace test suite, the pybergshamra suite (167 passed and 20
skipped), and the server-side pyFF pipeline suite (52 passed and 1 skipped) all
passed with the optimized build.

## Consequences

Positive consequences:

- Large aggregate signing no longer pays a digest update for each punctuation
  or escaped byte.
- Exclusive C14N avoids repeated ancestor walks and whole-map clones.
- Canonical rendering avoids temporary final strings for namespace
  declarations and attributes.
- Memory remains bounded with respect to the digest stream, and measured peak
  memory did not regress.
- The same implementation improves both aggregate signing and full MDQ work.

Negative consequences:

- Each active reference digest reserves a 64 KiB buffer.
- Exclusive C14N now has more mutable traversal state and relies on correctly
  paired apply/restore operations.
- Owned attribute and namespace sorting allocations remain; eliminating those
  requires the more extensive design described by ADR-0010.

## Relationship to Earlier Decisions

This decision extends ADR-0008's document-native, streaming signing design. It
does not replace that architecture or expose a new public signing API.

It partially realizes the rendering goal in ADR-0010 by streaming final bytes,
but it does not implement the proposed fully borrowed attribute and namespace
representation. ADR-0010 remains a separate proposed decision.
