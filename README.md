# Canary Evidence Chain

**Mints canary markers into synthetic data this package generates itself, then proves — with a
payload-free, hash-linked evidence chain — when one of those markers reappears in text you
control.**

MIT licensed · zero runtime dependencies · MCP stdio server · TypeScript

## The security problem

You share an evaluation corpus with a vendor, a model provider, or an internal team. Later you
want to know whether that data spread beyond where you released it — into a retrieval index, a
model context, a support export, a leaked dump. Ordinary logging cannot answer it, and the
answer needs to survive scrutiny: an evidence record that has not been quietly edited after the
fact.

## What this product does

You generate a synthetic dataset inside this package, mint a canary marker bound to one of its
records and one recipient label, hand that marker to exactly one recipient, and later scan text
you already control. If the marker comes back, you have evidence that data released to one
recipient reached a place you did not release it to — recorded as a payload-free, hash-linked
evidence entry whose export verifies as a pure function of its own bytes.

### Major capabilities

- **Deterministic synthetic datasets.** Generated from a fixed 32-bit seed, so a dataset is
  reproducible and never clock-derived.
- **Bound canary markers.** Each marker binds one generated record to one recipient label. The
  marker value is returned to the caller exactly once and is not retrievable afterwards through
  any public operation.
- **Streaming detection.** `scan_for_canaries` scans caller-supplied text or an async chunk
  stream for known markers.
- **Hash-linked evidence.** Entries store digests, never payloads or marker values; export
  verification is pure and offline.
- **Session-local containment.** A trip sets a containment flag reported to the caller — never
  an action taken against a person or a third-party system.
- **Honeypot record registration.** Register a generated record as a honeypot and report access
  observations against it, on the same evidence chain.

## The synthetic-test-data-only boundary

This is a deliberate product boundary, technically enforced, not a disclaimer:

- Canaries can only be minted against datasets this package generated itself. There is no
  constructor or cast path that accepts caller-supplied "real" records.
- Recipient labels that look like real-world identifiers (e-mail, URL, hostname, IP address,
  phone number, IBAN, payment card, cloud ARN or access key) are rejected by shape, naming the
  class that matched.
- Seeds must be fixed 32-bit integers.
- Evidence entries store digests only; a marker value is never re-exposed.
- The package has no network, filesystem-write, or process-execution capability, verified by a
  build-failing symbol scan.

**Honest limitation, preserved from the specification:** an operator could manually copy a
synthetic canary marker into production data or into somebody else's dataset. This package
cannot prevent that. It constrains what the software does, not what a human chooses to do with
a string it handed them.

## Install and run

Prerequisites: [Bun](https://bun.sh) 1.1+ (or Node 22+ with a TypeScript loader). No runtime
dependencies to install.

```bash
git clone https://github.com/SweetKenneth/shpbl-canary-chain.git
cd shpbl-canary-chain
bun install                    # dev types only
bun test                       # conformance suite
bun run scripts/symbol-scan.ts # build-failing forbidden-capability scan
bun src/mcp-server.ts          # MCP server: newline-delimited JSON-RPC 2.0 on stdin/stdout
```

### MCP configuration

```json
{
  "mcpServers": {
    "canary-chain": {
      "command": "bun",
      "args": ["/absolute/path/to/shpbl-canary-chain/src/mcp-server.ts"]
    }
  }
}
```

### Tool surface

| Tool | Purpose |
|---|---|
| `generate_synthetic_dataset` | deterministically generate a package-owned synthetic dataset |
| `mint_canary` | mint a marker bound to one generated record and one recipient label |
| `register_honeypot` | register a generated record as a honeypot |
| `report_access` | record an access observation against a honeypot |
| `scan_for_canaries` | scan caller-supplied text or an async chunk stream for known markers |
| `export_evidence` | export the payload-free, hash-linked evidence chain and verify it |
| `get_stats` | per-dataset and per-recipient canary and trip counts |
| `describe_policy` | seed rules, limits, identifier-shape classes, hash algorithm |
| `reset_state` | clear session state; previously exported evidence is unaffected |

### Worked example

`examples/worked-example.ts` generates a dataset, mints a canary for one recipient, scans clean
text, then scans text containing the marker, and exports and verifies the resulting evidence
chain.

```bash
bun examples/worked-example.ts
```

## Verification results

25 conformance tests, 72 assertions: specification properties P1–P13, every §7 failure mode,
the export allowlist, and the MCP JSON-RPC surface. Forbidden-symbol scan covers 8 source files
with 0 findings. Strict typecheck is clean. Runtime dependencies: **zero**.

## Security boundaries

**Protects against:** a synthetic evaluation dataset released to one recipient turning up in
text you control but never released it to. The evidence chain makes the recurrence provable
after the fact and resistant to quiet editing.

**Does not protect against:** the leak itself, or attribution of blame. A trip proves the marker
reappeared in text you scanned. It does not prove who moved it.

Refused capabilities: network access of any kind, filesystem writes, process execution, foreign
closure references. Evidence persistence happens only through a sink the caller supplies; if
that sink rejects a write, the entry is discarded and the chain head is left unchanged.

See `SECURITY.md` for the full threat model and misuse boundary.

## Known limitations

- An operator can manually copy a synthetic marker into production data. The package cannot
  prevent that, and does not claim to.
- A trip is evidence of recurrence, not of who caused it.
- Scanning covers only text the caller supplies; the package never discovers or fetches content.

## Provenance

Discovered with SHPBL. This product originated through cross-capability composition in the
SHPBL capability library. Its public implementation was independently built from a published
behavioural specification. SHPBL's proprietary capability library, discovery system, harvested
implementation bodies, and private provenance machinery are not included.

- Public behavioural specification: <https://github.com/SweetKenneth/shpbl-spec-canary-chain>
  (a copy ships here as `SPEC-canary-evidence-chain.md`)
- SHPBL: <https://shpbl.com>
- Details: `PROVENANCE.md`

## Tenable status

Submitted to the [Tenable CyberAgents Exchange for review on September 11, 2026](https://github.com/tenable/cyberagents-exchange/pull/168).
Submission does not imply review, approval, certification, validation, endorsement, or acceptance by Tenable.

## SHPBL Agent Evidence series

Independently installable, interoperable at the evidence-record boundary:

- [shpbl-action-ledger](https://github.com/SweetKenneth/shpbl-action-ledger) — agent action evidence ledger
- [shpbl-handoff-attestor](https://github.com/SweetKenneth/shpbl-handoff-attestor) — cross-agent handoff attestation
- [shpbl-drift-sentinel](https://github.com/SweetKenneth/shpbl-drift-sentinel) — agent behaviour drift detection
- [shpbl-retrieval-auditor](https://github.com/SweetKenneth/shpbl-retrieval-auditor) — retrieval context provenance
- [shpbl-canary-chain](https://github.com/SweetKenneth/shpbl-canary-chain) — synthetic canary evidence chain

## Licence

MIT — Copyright (c) 2026 Kenneth E. Sweet Jr. See `LICENSE`.
