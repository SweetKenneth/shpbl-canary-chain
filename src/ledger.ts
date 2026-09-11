/**
 * Payload-free, hash-linked evidence records, compatible with the Agent Action Evidence
 * Ledger's canonical form and chain rule (SPEC invariant 7 / P9): an entry produced here
 * verifies inside such a ledger's export unchanged.
 */
import { canonical, digestOf, Json, sha256, CanaryError } from "./canonical.js";

export interface EvidenceEntry {
  sequence: number;
  kind: string;
  prevDigest: string;
  entryDigest: string;
  [k: string]: Json;
}

export const GENESIS_DIGEST = "0".repeat(64);

export interface EvidenceSink {
  append(entry: EvidenceEntry, expectedHead: string): Promise<{ ok: true } | { ok: false; reason?: string }>;
}

function entryBody(e: Omit<EvidenceEntry, "entryDigest">): Json {
  const { sequence, kind, prevDigest, ...rest } = e;
  const keys = Object.keys(rest).sort();
  const out: Record<string, Json> = { sequence: sequence as Json, kind: kind as Json, prevDigest: prevDigest as Json };
  for (const k of keys) out[k] = rest[k] as Json;
  return out as Json;
}

/**
 * Evidence is session-local unless a caller-supplied sink is provided (SPEC §3.5 /
 * invariant 4). The package never opens a sink itself: no file, no network, no process.
 */
export class EvidenceChain {
  private records: EvidenceEntry[] = [];
  private sink?: EvidenceSink;

  constructor(sink?: EvidenceSink) {
    this.sink = sink;
  }

  get length(): number {
    return this.records.length;
  }

  private head(): string {
    return this.records.length ? this.records[this.records.length - 1]!.entryDigest : GENESIS_DIGEST;
  }

  async append(kind: string, fields: Record<string, Json>): Promise<EvidenceEntry> {
    const prevDigest = this.head();
    const body: Omit<EvidenceEntry, "entryDigest"> = {
      sequence: this.records.length + 1,
      kind,
      prevDigest,
      ...fields,
    };
    const entryDigest = sha256(canonical(entryBody(body)));
    const entry: EvidenceEntry = { ...(body as EvidenceEntry), entryDigest };

    if (this.sink) {
      const result = await this.sink.append(entry, prevDigest);
      if (!result.ok) {
        throw new CanaryError("E_STORE", "evidence sink rejected the entry; chain head unchanged");
      }
    }
    this.records.push(entry);
    return entry;
  }

  export(): { entries: EvidenceEntry[]; exportDigest: string } {
    return { entries: [...this.records], exportDigest: digestOf(this.records as unknown as Json) };
  }

  reset(): void {
    this.records = [];
  }
}

/** Independent verifier: usable by an operator on any export of these entries. */
export function verifyChain(entries: EvidenceEntry[]): { valid: boolean; brokenAt?: number; reason?: string } {
  let prev = GENESIS_DIGEST;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    if (e.sequence !== i + 1) return { valid: false, brokenAt: i + 1, reason: "sequence" };
    if (e.prevDigest !== prev) return { valid: false, brokenAt: e.sequence, reason: "chain-link" };
    const { entryDigest, ...rest } = e;
    if (sha256(canonical(entryBody(rest as Omit<EvidenceEntry, "entryDigest">))) !== entryDigest) {
      return { valid: false, brokenAt: e.sequence, reason: "entry-digest" };
    }
    prev = entryDigest;
  }
  return { valid: true };
}
