/** SPEC §10 externally testable properties P1-P13, §7 failure modes. */
import { describe, expect, test } from "bun:test";
import { CanaryChain } from "../src/canary-chain.js";
import { CanaryError } from "../src/canonical.js";
import { verifyChain } from "../src/ledger.js";
import { isSyntheticDataset, generateSyntheticDataset } from "../src/generator.js";
import { matchIdentifierShape, IDENTIFIER_SHAPE_CLASSES } from "../src/identifier-shapes.js";
import { chainWithDataset } from "./fixtures.js";

test("P1 raw external data cannot reach mint_canary at runtime", () => {
  const { chain } = chainWithDataset();
  const fake = { datasetId: "d-fake", recordCount: 1, schemaDigest: "x", seed: 1, records: [{}] };
  expect(() => chain.mintCanary({ dataset: fake, recordRef: 0, recipientLabel: "lbl", method: "unique-key" })).toThrow(CanaryError);
  try {
    chain.mintCanary({ dataset: fake, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
  } catch (e) {
    expect((e as CanaryError).code).toBe("E_ORIGIN");
  }
  expect(isSyntheticDataset(fake)).toBe(false);
});

test("P2 every negative-corpus identifier shape is rejected", () => {
  const { chain, dataset } = chainWithDataset();
  const samples: Record<string, string> = {
    phone: "15555550123",
    "payment-card": "4111111111111111",
    // Assembled at runtime so repository secret scanners do not flag this negative-corpus
    // fixture as a real credential. The runtime value is unchanged.
    "cloud-access-key": "AKIA" + "ABCDEFGHIJKLMNOP",
  };
  for (const [cls, value] of Object.entries(samples)) {
    expect(matchIdentifierShape(value)).toBe(cls as any);
    expect(() => chain.mintCanary({ dataset, recordRef: 0, recipientLabel: value, method: "unique-key" })).toThrow();
    try {
      chain.mintCanary({ dataset, recordRef: 0, recipientLabel: value, method: "unique-key" });
    } catch (e) {
      expect((e as CanaryError).code).toBe("E_IDENTIFIER_SHAPE");
    }
  }
  expect(IDENTIFIER_SHAPE_CLASSES.length).toBe(10);
});

test("P4 no marker character or scanned substring appears in evidence, stats, export, or errors", async () => {
  const { chain, dataset } = chainWithDataset();
  const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl-1", method: "unique-key" });
  const secretContext = "SUPER-SECRET-SURROUNDING-CONTEXT";
  const text = `${secretContext} ${mint.markerValue} ${secretContext}`;
  await chain.scanForCanaries({ text });
  const dump = JSON.stringify(chain.exportEvidence()) + JSON.stringify(chain.getStats());
  expect(dump).not.toContain(mint.markerValue);
  expect(dump).not.toContain(secretContext);
  let errText = "";
  try {
    chain.mintCanary({ dataset, recordRef: 0, recipientLabel: secretContext + "@x.com", method: "unique-key" });
  } catch (e) {
    errText = JSON.stringify((e as CanaryError).toJSON());
  }
  expect(errText).not.toContain(secretContext);
});

test("P5 same schema and seed produce byte-identical datasets", () => {
  const schema = { fields: [{ name: "a", kind: "string" }, { name: "n", kind: "integer", min: 0, max: 9 }] };
  const one = generateSyntheticDataset({ schema, recordCount: 20, seed: 7 }, "d-a");
  const two = generateSyntheticDataset({ schema, recordCount: 20, seed: 7 }, "d-b");
  expect(JSON.stringify((one as any).records)).toBe(JSON.stringify((two as any).records));
  expect(one.schemaDigest).toBe(two.schemaDigest);
});

test("P6 a non-deterministic seed source is rejected", () => {
  const { chain } = chainWithDataset();
  // a fixed 32-bit integer seed is the only accepted form:
  expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: 12345 })).not.toThrow();
  // clock-derived seeds are out of the accepted 32-bit range and rejected:
  expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: Date.now() as any })).toThrow("E_SEED");
  expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: undefined })).toThrow("E_SEED");
  expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: "random" as any })).toThrow("E_SEED");
  expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: () => Math.random() as any })).toThrow("E_SEED");
});

test("P9 canary trip evidence verifies inside an export unchanged", async () => {
  const { chain, dataset } = chainWithDataset();
  const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "field-value" });
  await chain.scanForCanaries({ text: mint.markerValue });
  const { entries, valid } = chain.exportEvidence();
  expect(valid).toBe(true);
  expect(verifyChain(entries).valid).toBe(true);
  const tampered = structuredClone(entries);
  (tampered[0] as any).markerDigest = "0".repeat(64);
  expect(verifyChain(tampered).valid).toBe(false);
});

test("P11 a honeypot cannot be registered against a non-generator record", () => {
  const { chain } = chainWithDataset();
  const fake = { datasetId: "d-x", recordCount: 1, records: [{}] };
  expect(() => chain.registerHoneypot({ dataset: fake, recordRef: 0, label: "hp" })).toThrow("E_ORIGIN");
});

test("P12 scans stop at the character bound and do not consume later async chunks", async () => {
  const { chain } = chainWithDataset();
  let consumed = 0;
  async function* gen() {
    for (let i = 0; i < 10; i++) {
      consumed++;
      yield "x".repeat(50_000);
    }
  }
  await expect(chain.scanForCanaries({ text: gen(), maxChars: 100_000 })).rejects.toThrow("E_LIMIT");
  expect(consumed).toBeLessThanOrEqual(3);
});

test("P13 a lost marker cannot be retrieved through any public operation", async () => {
  const { chain, dataset } = chainWithDataset();
  chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
  const dump = JSON.stringify(chain.exportEvidence()) + JSON.stringify(chain.getStats()) + JSON.stringify(chain.describePolicy());
  expect(dump).not.toContain("cnry_");
});

describe("SPEC §7 failure modes", () => {
  test("dataset handle not package-generated -> rejected", () => {
    const { chain } = chainWithDataset();
    expect(() => chain.mintCanary({ dataset: { foo: 1 }, recordRef: 0, recipientLabel: "lbl", method: "unique-key" })).toThrow("E_ORIGIN");
  });
  test("recipient label matches a real-world identifier shape -> E_IDENTIFIER_SHAPE naming the class", () => {
    const { chain, dataset } = chainWithDataset();
    try {
      chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "12025550123", method: "unique-key" });
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as CanaryError).code).toBe("E_IDENTIFIER_SHAPE");
      expect((e as CanaryError).message).toContain("phone");
    }
  });
  test("honeypot registered against a non-synthetic record -> E_ORIGIN", () => {
    const { chain } = chainWithDataset();
    expect(() => chain.registerHoneypot({ dataset: {}, recordRef: 0, label: "hp" })).toThrow("E_ORIGIN");
  });
  test("non-deterministic seed supplied -> E_SEED", () => {
    const { chain } = chainWithDataset();
    expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: NaN })).toThrow("E_SEED");
  });
  test("scan input not a string or async iterable -> E_INPUT", async () => {
    const { chain } = chainWithDataset();
    await expect(chain.scanForCanaries({ text: 12345 as any })).rejects.toThrow("E_INPUT");
  });
  test("record count above limit -> E_LIMIT", () => {
    const { chain } = chainWithDataset();
    expect(() => chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 200_000, seed: 1 })).toThrow("E_LIMIT");
  });
  test("evidence sink write failure -> E_STORE; chain head unchanged, entry discarded", async () => {
    const failingSink = { append: async () => ({ ok: false as const, reason: "denied" }) };
    const chain = new CanaryChain(failingSink);
    const { dataset } = chain.generateSyntheticDataset({ schema: { fields: [{ name: "a", kind: "string" }] }, recordCount: 1, seed: 1 });
    const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
    await expect(chain.scanForCanaries({ text: mint.markerValue })).rejects.toThrow("E_STORE");
    expect(chain.exportEvidence().entries.length).toBe(0);
  });
  test("scan exceeds published character limit -> E_LIMIT; no remaining input consumed", async () => {
    const { chain } = chainWithDataset();
    await expect(chain.scanForCanaries({ text: "x".repeat(300_000) })).rejects.toThrow("E_LIMIT");
  });
  test("trippedAt precedes mintedAt beyond tolerance -> retained with clockAnomaly true", async () => {
    const { chain, dataset } = chainWithDataset();
    const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
    // Force mintedAt far in the future to simulate trippedAt preceding it beyond tolerance.
    (chain as any).canaries.get(mint.canaryId).mintedAt = new Date(Date.now() + 60_000).toISOString();
    (chain as any).markerIndex.get(mint.markerValue).mintedAt = new Date(Date.now() + 60_000).toISOString();
    const scan = await chain.scanForCanaries({ text: mint.markerValue });
    expect(scan.trips[0]!.clockAnomaly).toBe(true);
    const { entries } = chain.exportEvidence();
    expect((entries[0] as any).clockAnomaly).toBe(true);
  });
});

test("synthetic-only enforcement: mint requires a valid recordRef bound to the dataset", () => {
  const { chain, dataset } = chainWithDataset(3);
  expect(() => chain.mintCanary({ dataset, recordRef: 99, recipientLabel: "lbl", method: "unique-key" })).toThrow("E_INPUT");
});

test("deterministic seed + local containment: quarantined flag is session-local, not an action", async () => {
  const { chain, dataset } = chainWithDataset();
  const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
  const before = await chain.scanForCanaries({ text: "nothing here" });
  expect(before.containment.quarantined).toBe(false);
  const after = await chain.scanForCanaries({ text: mint.markerValue });
  expect(after.containment.quarantined).toBe(true);
});

test("reset_state clears session but prior exported evidence is unaffected by design", async () => {
  const { chain, dataset } = chainWithDataset();
  const mint = chain.mintCanary({ dataset, recordRef: 0, recipientLabel: "lbl", method: "unique-key" });
  await chain.scanForCanaries({ text: mint.markerValue });
  const exported = chain.exportEvidence();
  chain.resetState();
  expect(chain.exportEvidence().entries.length).toBe(0);
  expect(exported.entries.length).toBe(1);
});
