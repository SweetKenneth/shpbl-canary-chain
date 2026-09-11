# Security policy and threat model

## Threat model

**Protects against:** a synthetic evaluation dataset released to one recipient turning up in
text you control but never released it to — a leaked corpus, an unexpected retrieval index, a
model context, a support export. The evidence chain makes the recurrence provable after the
fact and resistant to quiet editing: entries are hash-linked and verification is a pure
function over an export.

**Does not protect against:** the leak itself, attribution of blame, or anything about a party
you have no data from. A trip proves the marker reappeared in text you scanned. It does not
prove who moved it.

## Refused capabilities

Verified by `scripts/symbol-scan.ts` on every run:

- no network access of any kind;
- no filesystem writes;
- no process execution;
- no foreign closure references.

Evidence persistence happens only through a sink the caller supplies. If that sink rejects a
write, the entry is discarded and the chain head is left unchanged.

## Misuse boundary

This is not a surveillance or deception product, and it is built so that it cannot quietly
become one:

- canaries exist only inside datasets this package generated;
- recipient labels matching real-world identifier shapes are rejected;
- evidence records digests, never payloads or marker values;
- a marker value is returned once and is never retrievable again;
- "containment" is a session-local flag reported to the caller, not an action against a person
  or a third-party system.

**Standing limitation, preserved from the specification:** an operator could manually copy a
synthetic marker into production data. The package cannot prevent that, and does not claim to.

## Reporting a vulnerability

Open a GitHub security advisory on this repository, or contact the maintainer directly. Please
do not open a public issue for a suspected vulnerability before it has been triaged.
