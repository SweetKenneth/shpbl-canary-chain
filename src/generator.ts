/**
 * Seeded synthetic-dataset generator (SPEC §3.1 / invariant 8 / P5, P6).
 *
 * The dataset handle is a nominally-branded type: the brand is an unexported module-local
 * symbol, so no object literal built outside this module can satisfy the published
 * `SyntheticDataset` type, and no public constructor or cast path exists (SPEC §3.2, P1).
 * `generateSyntheticDataset` is the only function in the published surface that can produce
 * one.
 */
import { CanaryError, Json, requireId, requireInt } from "./canonical.js";

const BRAND: unique symbol = Symbol("canary-chain:synthetic-dataset");

export interface SyntheticDataset {
  readonly datasetId: string;
  readonly recordCount: number;
  readonly schemaDigest: string;
  readonly seed: number;
  readonly [BRAND]: true;
}

interface InternalDataset extends SyntheticDataset {
  records: Json[];
}

export function isSyntheticDataset(v: unknown): v is SyntheticDataset {
  return typeof v === "object" && v !== null && (v as Record<PropertyKey, unknown>)[BRAND] === true;
}

export function recordsOf(d: SyntheticDataset): Json[] {
  if (!isSyntheticDataset(d)) {
    throw new CanaryError("E_ORIGIN", "dataset was not produced by this package's generator", "dataset");
  }
  return (d as InternalDataset).records;
}

export type FieldSpec =
  | { name: string; kind: "string" }
  | { name: string; kind: "integer"; min: number; max: number }
  | { name: string; kind: "boolean" }
  | { name: string; kind: "enum"; values: string[] }
  | { name: string; kind: "uuid" };

export interface Schema {
  fields: FieldSpec[];
}

const SYNTHETIC_WORDS = [
  "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
  "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo",
  "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu",
];

const FIELD_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** mulberry32: deterministic, fast, no external dependency. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function validateSchema(schema: unknown): Schema {
  if (typeof schema !== "object" || schema === null || !Array.isArray((schema as any).fields)) {
    throw new CanaryError("E_INPUT", "schema must be an object with a fields array", "schema");
  }
  const fields = (schema as any).fields as unknown[];
  if (fields.length === 0 || fields.length > 64) {
    throw new CanaryError("E_INPUT", "schema must declare between 1 and 64 fields", "schema.fields");
  }
  const names = new Set<string>();
  const out: FieldSpec[] = fields.map((raw) => {
    const f = raw as Record<string, unknown>;
    const name = f.name;
    if (typeof name !== "string" || !FIELD_NAME_RE.test(name)) {
      throw new CanaryError("E_INPUT", "field name must be a short identifier", "schema.fields[].name");
    }
    if (names.has(name)) throw new CanaryError("E_INPUT", "duplicate field name", "schema.fields[].name");
    names.add(name);
    switch (f.kind) {
      case "string":
        return { name, kind: "string" };
      case "boolean":
        return { name, kind: "boolean" };
      case "uuid":
        return { name, kind: "uuid" };
      case "integer": {
        const min = f.min;
        const max = f.max;
        if (typeof min !== "number" || typeof max !== "number" || !Number.isInteger(min) || !Number.isInteger(max) || min > max) {
          throw new CanaryError("E_INPUT", "integer field requires integer min <= max", "schema.fields[].min");
        }
        return { name, kind: "integer", min, max };
      }
      case "enum": {
        const values = f.values;
        if (!Array.isArray(values) || values.length === 0 || !values.every((v) => typeof v === "string")) {
          throw new CanaryError("E_INPUT", "enum field requires a non-empty string values array", "schema.fields[].values");
        }
        return { name, kind: "enum", values: values as string[] };
      }
      default:
        throw new CanaryError("E_INPUT", "unsupported field kind", "schema.fields[].kind");
    }
  });
  return { fields: out };
}

/**
 * Non-deterministic seed sources are rejected (invariant 8, P6): a seed must be a fixed,
 * finite, non-negative safe integer supplied by the caller. Anything derived from a clock,
 * random source, or non-integral value is out of type and out of range.
 */
function validateSeed(seed: unknown): number {
  if (typeof seed !== "number" || !Number.isInteger(seed) || seed < 0 || seed > 0x7fffffff || Number.isNaN(seed)) {
    throw new CanaryError("E_SEED", "seed must be a fixed non-negative 32-bit integer", "seed");
  }
  return seed;
}

function schemaDigestOf(schema: Schema): string {
  const { sha256, canonical } = require("./canonical.js") as typeof import("./canonical.js");
  return sha256(canonical(schema as unknown as Json));
}

export function generateSyntheticDataset(input: { schema: unknown; recordCount: unknown; seed: unknown }, datasetId: string): InternalDataset {
  const schema = validateSchema(input.schema);
  const recordCount = requireInt(input.recordCount, "recordCount", 1, 100_000);
  const seed = validateSeed(input.seed);
  const rng = mulberry32(seed);

  const records: Json[] = [];
  for (let i = 0; i < recordCount; i++) {
    const record: Record<string, Json> = {};
    for (const f of schema.fields) {
      record[f.name] = generateValue(f, rng);
    }
    records.push(record as Json);
  }

  const schemaDigest = schemaDigestOf(schema);
  const dataset: InternalDataset = {
    datasetId: requireId(datasetId, "datasetId"),
    recordCount,
    schemaDigest,
    seed,
    records,
    [BRAND]: true,
  };
  return dataset;
}

function generateValue(f: FieldSpec, rng: () => number): Json {
  switch (f.kind) {
    case "string": {
      const w1 = SYNTHETIC_WORDS[Math.floor(rng() * SYNTHETIC_WORDS.length)];
      const w2 = SYNTHETIC_WORDS[Math.floor(rng() * SYNTHETIC_WORDS.length)];
      const n = Math.floor(rng() * 10000);
      return `synthetic-${w1}-${w2}-${n}`;
    }
    case "integer":
      return f.min + Math.floor(rng() * (f.max - f.min + 1));
    case "boolean":
      return rng() < 0.5;
    case "enum":
      return f.values[Math.floor(rng() * f.values.length)]!;
    case "uuid": {
      const hex = () => Math.floor(rng() * 16).toString(16);
      const seg = (n: number) => Array.from({ length: n }, hex).join("");
      return `${seg(8)}-${seg(4)}-4${seg(3)}-a${seg(3)}-${seg(12)}`;
    }
  }
}
