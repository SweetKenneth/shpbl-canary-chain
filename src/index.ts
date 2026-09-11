/**
 * Public export allowlist (SPEC invariant 9, P7). Adding an export here without an
 * accompanying allowlist-test update fails `tests/export-allowlist.test.ts`.
 *
 * No raw-data constructor for `SyntheticDataset` is exported: the only way to obtain one
 * is `generateSyntheticDataset`/`CanaryChain.generateSyntheticDataset` (SPEC §3.2, P1).
 */
export { CanaryChain } from "./canary-chain.js";
export type { MintCanaryOutcome, MintMethod, MintResult, Policy, ScanResult } from "./canary-chain.js";
export { CanaryError, canonical, digestOf, sha256 } from "./canonical.js";
export { EvidenceChain, GENESIS_DIGEST, verifyChain } from "./ledger.js";
export type { EvidenceEntry, EvidenceSink } from "./ledger.js";
export { IDENTIFIER_SHAPE_CLASSES, matchIdentifierShape } from "./identifier-shapes.js";
export type { IdentifierShapeClass } from "./identifier-shapes.js";
export { generateSyntheticDataset, isSyntheticDataset } from "./generator.js";
export type { FieldSpec, Schema, SyntheticDataset } from "./generator.js";
export { TOOLS, callTool } from "./tools.js";
