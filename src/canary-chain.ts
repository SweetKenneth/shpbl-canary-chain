/**
 * Canary Evidence Chain — core session logic (SPEC §3-§7).
 *
 * Enforces, by construction:
 *  - synthetic-only origin (invariant 1, P1): mint/honeypot only accept a
 *    SyntheticDataset handle produced by this package's own generator.
 *  - opaque recipients + identifier-shape rejection (invariant 2, P2).
 *  - zero egress (invariant 3): no network/process/filesystem symbol appears here.
 *  - no ambient persistence (invariant 4): evidence is session-local unless the
 *    caller supplies a sink; this module never opens one itself.
 *  - payload-free evidence (invariant 5, P4): marker values and scanned text are
 *    never placed into an evidence entry, stat, export, error, or log.
 *  - local containment only (invariant 6): `quarantined` is a session-read flag,
 *    never an action.
 *  - deterministic generation (invariant 8, P5/P6), delegated to generator.ts.
 */
import { randomBytes } from "node:crypto";
import { CanaryError, Json, digestOf, requireId, requireInt, sha256 } from "./canonical.js";
import { EvidenceChain, EvidenceEntry, EvidenceSink, verifyChain } from "./ledger.js";
import { IDENTIFIER_SHAPE_CLASSES, matchIdentifierShape } from "./identifier-shapes.js";
import { generateSyntheticDataset, recordsOf, SyntheticDataset } from "./generator.js";

export const RECIPIENT_LABEL_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const HONEYPOT_LABEL_RE = /^[A-Za-z0-9_-]{1,64}$/;
export type MintMethod = "field-value" | "record-append" | "unique-key";
const MINT_METHODS: MintMethod[] = ["field-value", "record-append", "unique-key"];

export const DEFAULT_MAX_CHARS = 200_000;
export const HARD_MAX_CHARS = 1_000_000;
/** Clock-skew tolerance for `trippedAt` preceding `mintedAt` (SPEC §7). */
export const CLOCK_SKEW_TOLERANCE_MS = 5_000;
export const FORMAT_VERSION = "1.0";
export const IDENTIFIER_SHAPE_CORPUS_VERSION = "1.0";

export interface MintResult {
  canaryId: string;
  datasetId: string;
  method: MintMethod;
  recipientLabel: string;
  mintedAt: string;
  markerDigest: string;
}

export interface MintCanaryOutcome extends MintResult {
  /** Returned exactly once, only from mint_canary, never persisted or resurfaced. */
  markerValue: string;
}

interface ArmedCanary {
  canaryId: string;
  datasetId: string;
  method: MintMethod;
  recipientLabel: string;
  mintedAt: string;
  markerDigest: string;
  markerValue: string;
  tripped: boolean;
}

interface ArmedHoneypot {
  honeypotId: string;
  datasetId: string;
  recordRef: number;
  label: string;
  registeredAt: string;
  accessed: boolean;
}

export interface ScanResult {
  trips: Array<{ canaryId: string; datasetId: string; recipientLabel: string; clockAnomaly?: true }>;
  scannedChars: number;
  containment: { quarantined: boolean };
}

export interface Policy {
  defaultMaxChars: number;
  hardMaxChars: number;
  clockSkewToleranceMs: number;
  identifierShapeClasses: readonly string[];
  identifierShapeCorpusVersion: string;
  formatVersion: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

/** A caller-visible seed must be a fixed literal number; anything else is non-deterministic. */
function isPlainSeed(seed: unknown): boolean {
  return typeof seed === "number";
}

export class CanaryChain {
  private datasets = new Map<string, SyntheticDataset>();
  private canaries = new Map<string, ArmedCanary>();
  private markerIndex = new Map<string, ArmedCanary>(); // markerValue -> canary
  private honeypots = new Map<string, ArmedHoneypot>();
  private chain: EvidenceChain;
  private datasetSeq = 0;
  private canarySeq = 0;
  private honeypotSeq = 0;

  constructor(sink?: EvidenceSink) {
    this.chain = new EvidenceChain(sink);
  }

  // ---- 3.1 generate_synthetic_dataset ----------------------------------
  generateSyntheticDataset(input: { schema: unknown; recordCount: unknown; seed: unknown }): {
    dataset: SyntheticDataset;
    datasetId: string;
    recordCount: number;
    seed: number;
    schemaDigest: string;
  } {
    if (!isPlainSeed(input?.seed)) {
      throw new CanaryError("E_SEED", "seed must be a fixed non-negative 32-bit integer", "seed");
    }
    if (typeof input?.recordCount === "number" && input.recordCount > 100_000) {
      throw new CanaryError("E_LIMIT", "recordCount exceeds the published maximum of 100000", "recordCount");
    }
    this.datasetSeq += 1;
    const datasetId = `d-${this.datasetSeq}`;
    const dataset = generateSyntheticDataset(input, datasetId);
    this.datasets.set(datasetId, dataset);
    return {
      dataset,
      datasetId: dataset.datasetId,
      recordCount: dataset.recordCount,
      seed: dataset.seed,
      schemaDigest: dataset.schemaDigest,
    };
  }

  // ---- 3.2 mint_canary ---------------------------------------------------
  mintCanary(input: {
    dataset: unknown;
    recordRef: unknown;
    recipientLabel: unknown;
    method: unknown;
  }): MintCanaryOutcome {
    // No public constructor reaches a value that satisfies SyntheticDataset (P1, type
    // level); this is the runtime defence-in-depth check (SPEC §7 row 1).
    const records = recordsOf(input.dataset as SyntheticDataset);
    const dataset = input.dataset as SyntheticDataset;

    const recordRef = requireInt(input.recordRef, "recordRef", 0, Math.max(records.length - 1, 0));
    if (records.length === 0) {
      throw new CanaryError("E_INPUT", "dataset has no records", "recordRef");
    }

    const recipientLabel = requireId(input.recipientLabel, "recipientLabel");
    if (!RECIPIENT_LABEL_RE.test(recipientLabel)) {
      throw new CanaryError("E_INPUT", "recipientLabel does not match the published pattern", "recipientLabel");
    }
    const shape = matchIdentifierShape(recipientLabel);
    if (shape) {
      throw new CanaryError("E_IDENTIFIER_SHAPE", `recipientLabel matches the ${shape} identifier shape`, "recipientLabel");
    }

    if (typeof input.method !== "string" || !MINT_METHODS.includes(input.method as MintMethod)) {
      throw new CanaryError("E_INPUT", "method must be one of field-value, record-append, unique-key", "method");
    }
    const method = input.method as MintMethod;

    this.canarySeq += 1;
    const canaryId = `c-${String(this.canarySeq).padStart(4, "0")}`;
    const markerValue = `cnry_${randomBytes(24).toString("hex")}`;
    const markerDigest = sha256(markerValue);
    const mintedAt = nowIso();

    const armed: ArmedCanary = {
      canaryId,
      datasetId: dataset.datasetId,
      method,
      recipientLabel,
      mintedAt,
      markerDigest,
      markerValue,
      tripped: false,
    };
    this.canaries.set(canaryId, armed);
    this.markerIndex.set(markerValue, armed);

    return { canaryId, datasetId: dataset.datasetId, method, recipientLabel, mintedAt, markerDigest, markerValue };
  }

  // ---- 3.3 scan_for_canaries ----------------------------------------------
  async scanForCanaries(input: { text: unknown; maxChars?: unknown }): Promise<ScanResult> {
    const policy = this.describePolicy();
    let effective = policy.defaultMaxChars;
    if (input.maxChars !== undefined) {
      if (typeof input.maxChars !== "number" || !Number.isInteger(input.maxChars) || input.maxChars <= 0) {
        throw new CanaryError("E_INPUT", "maxChars must be a positive integer", "maxChars");
      }
      if (input.maxChars > policy.hardMaxChars) {
        throw new CanaryError("E_LIMIT", "maxChars exceeds the published hard maximum", "maxChars");
      }
      effective = input.maxChars;
    }

    let buffer: string;
    let scannedChars: number;

    if (typeof input.text === "string") {
      if (input.text.length > effective) {
        throw new CanaryError("E_LIMIT", "scan input exceeds the published character limit");
      }
      buffer = input.text;
      scannedChars = buffer.length;
    } else if (
      input.text !== null &&
      typeof input.text === "object" &&
      typeof (input.text as AsyncIterable<string>)[Symbol.asyncIterator] === "function"
    ) {
      const it = (input.text as AsyncIterable<string>)[Symbol.asyncIterator]();
      let total = 0;
      let parts = "";
      let overflowed = false;
      // Stops before examining more input the instant a chunk would cross the bound
      // (SPEC §3.3, P12): the offending chunk is discarded and no further chunk is
      // ever requested from the iterator.
      while (true) {
        const { value, done } = await it.next();
        if (done) break;
        if (typeof value !== "string") {
          throw new CanaryError("E_INPUT", "async iterable must yield strings", "text");
        }
        if (total + value.length > effective) {
          overflowed = true;
          break;
        }
        total += value.length;
        parts += value;
      }
      if (overflowed) {
        throw new CanaryError("E_LIMIT", "scan input exceeds the published character limit");
      }
      buffer = parts;
      scannedChars = total;
    } else {
      throw new CanaryError("E_INPUT", "text must be a string or an async iterable of strings", "text");
    }

    const trips: ScanResult["trips"] = [];
    let anyMatch = false;
    for (const canary of this.markerIndex.values()) {
      if (!buffer.includes(canary.markerValue)) continue;
      anyMatch = true;
      canary.tripped = true;
      const trippedAt = nowIso();
      const clockAnomaly = Date.parse(trippedAt) < Date.parse(canary.mintedAt) - CLOCK_SKEW_TOLERANCE_MS;
      const fields: Record<string, Json> = {
        canaryId: canary.canaryId,
        datasetId: canary.datasetId,
        method: canary.method,
        recipientLabel: canary.recipientLabel,
        mintedAt: canary.mintedAt,
        trippedAt,
        markerDigest: canary.markerDigest,
      };
      if (clockAnomaly) fields.clockAnomaly = true;
      await this.chain.append("canary-trip", fields);
      trips.push({
        canaryId: canary.canaryId,
        datasetId: canary.datasetId,
        recipientLabel: canary.recipientLabel,
        ...(clockAnomaly ? { clockAnomaly: true as const } : {}),
      });
    }

    return { trips, scannedChars, containment: { quarantined: anyMatch } };
  }

  // ---- 3.4 register_honeypot ----------------------------------------------
  registerHoneypot(input: { dataset: unknown; recordRef: unknown; label: unknown }): {
    honeypotId: string;
    datasetId: string;
    recordRef: number;
    label: string;
    registeredAt: string;
  } {
    // Throws E_ORIGIN when the handle was not produced by this package's generator
    // (SPEC §3.4, §7, P11).
    const records = recordsOf(input.dataset as SyntheticDataset);
    const dataset = input.dataset as SyntheticDataset;
    const recordRef = requireInt(input.recordRef, "recordRef", 0, Math.max(records.length - 1, 0));
    if (records.length === 0) throw new CanaryError("E_INPUT", "dataset has no records", "recordRef");

    const label = requireId(input.label, "label");
    if (!HONEYPOT_LABEL_RE.test(label)) {
      throw new CanaryError("E_INPUT", "label does not match the published pattern", "label");
    }

    this.honeypotSeq += 1;
    const honeypotId = `h-${String(this.honeypotSeq).padStart(4, "0")}`;
    const registeredAt = nowIso();
    this.honeypots.set(honeypotId, {
      honeypotId,
      datasetId: dataset.datasetId,
      recordRef,
      label,
      registeredAt,
      accessed: false,
    });
    return { honeypotId, datasetId: dataset.datasetId, recordRef, label, registeredAt };
  }

  // ---- 3.6 report_access ---------------------------------------------------
  async reportAccess(input: { honeypotId: unknown; accessedAt?: unknown }): Promise<{ honeypotId: string; accessedAt: string }> {
    const honeypotId = requireId(input.honeypotId, "honeypotId");
    const honeypot = this.honeypots.get(honeypotId);
    if (!honeypot) throw new CanaryError("E_INPUT", "unknown honeypotId", "honeypotId");
    let accessedAt = nowIso();
    if (input.accessedAt !== undefined) {
      if (typeof input.accessedAt !== "string" || Number.isNaN(Date.parse(input.accessedAt))) {
        throw new CanaryError("E_INPUT", "accessedAt must be an ISO timestamp string", "accessedAt");
      }
      accessedAt = input.accessedAt;
    }
    honeypot.accessed = true;
    const clockAnomaly = Date.parse(accessedAt) < Date.parse(honeypot.registeredAt) - CLOCK_SKEW_TOLERANCE_MS;
    const fields: Record<string, Json> = {
      honeypotId,
      datasetId: honeypot.datasetId,
      label: honeypot.label,
      registeredAt: honeypot.registeredAt,
      accessedAt,
    };
    if (clockAnomaly) fields.clockAnomaly = true;
    await this.chain.append("honeypot-accessed", fields);
    return { honeypotId, accessedAt };
  }

  // ---- 3.6 get_stats ---------------------------------------------------------
  getStats(): { byDataset: Record<string, Json>; byRecipient: Record<string, Json> } {
    const byDataset: Record<string, { canaries: number; trips: number }> = {};
    const byRecipient: Record<string, { canaries: number; trips: number }> = {};
    for (const c of this.canaries.values()) {
      byDataset[c.datasetId] ??= { canaries: 0, trips: 0 };
      byDataset[c.datasetId]!.canaries += 1;
      if (c.tripped) byDataset[c.datasetId]!.trips += 1;
      byRecipient[c.recipientLabel] ??= { canaries: 0, trips: 0 };
      byRecipient[c.recipientLabel]!.canaries += 1;
      if (c.tripped) byRecipient[c.recipientLabel]!.trips += 1;
    }
    return { byDataset: byDataset as unknown as Record<string, Json>, byRecipient: byRecipient as unknown as Record<string, Json> };
  }

  // ---- 3.6 reset_state -------------------------------------------------------
  resetState(): { reset: true } {
    this.canaries.clear();
    this.markerIndex.clear();
    this.honeypots.clear();
    this.datasets.clear();
    this.chain.reset();
    this.datasetSeq = 0;
    this.canarySeq = 0;
    this.honeypotSeq = 0;
    return { reset: true };
  }

  // ---- 3.6 export_evidence ----------------------------------------------------
  exportEvidence(): { entries: EvidenceEntry[]; exportDigest: string; valid: boolean } {
    const { entries, exportDigest } = this.chain.export();
    return { entries, exportDigest, valid: verifyChain(entries).valid };
  }

  // ---- 3.6 describe_policy -----------------------------------------------------
  describePolicy(): Policy {
    return {
      defaultMaxChars: DEFAULT_MAX_CHARS,
      hardMaxChars: HARD_MAX_CHARS,
      clockSkewToleranceMs: CLOCK_SKEW_TOLERANCE_MS,
      identifierShapeClasses: IDENTIFIER_SHAPE_CLASSES,
      identifierShapeCorpusVersion: IDENTIFIER_SHAPE_CORPUS_VERSION,
      formatVersion: FORMAT_VERSION,
    };
  }
}
