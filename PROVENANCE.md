# Provenance

Discovered with SHPBL. This product originated through cross-capability composition in the
SHPBL capability library. Its public implementation was independently built from a published
behavioural specification. SHPBL's proprietary capability library, discovery system, harvested
implementation bodies, and private provenance machinery are not included.

The invention here — a payload-free, hash-linked evidence chain over synthetic canary data with
a technically enforced test-data-only boundary — was discovered by composing capability intent
across the SHPBL library and CMPSBL, a sister project by the same developer, Kenneth E. Sweet Jr.

## What this package contains

- Source written fresh from the frozen public behaviour specification
  <https://github.com/SweetKenneth/shpbl-spec-canary-chain> (a copy ships in this tree).
- No harvested SHPBL or CMPSBL capability body, normalized body, or prelude.
- No private SHPBL constants, thresholds, vocabulary, paths, seals, or provenance internals.
- No third-party code. Zero runtime dependencies.
- Digest computation is SHA-256 only.
- Author of every file in this tree: Kenneth E. Sweet Jr.

Every published constant in this package — the identifier-shape corpus, the seed rules, the
record and scan limits, the clock-skew tolerance — is this package's own, documented in the
specification, and tested against the specification's public properties rather than against
equality with any private SHPBL output.

## Release gates, cleared in order

1. conformance tests passing;
2. an exact-file IP surface review of every file that ships;
3. an explicit MIT implementation grant naming that exact reviewed file set;
4. licence file, release manifest and publication.

## Scope of the licence grant

The MIT grant in `LICENSE` covers the released files of this repository only. It is not a grant
over SHPBL, CMPSBL, the SHPBL capability library, harvested capability bodies, discovery
machinery, the Governor, private provenance records, or any other private system or future
product.

Tenable Exchange submission and Contribution Agreement acceptance are separate decisions and
have not been made.
