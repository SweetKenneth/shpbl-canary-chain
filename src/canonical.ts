// Canonical form + hashing. SHA-256 only, no other digest is produced anywhere.
import { createHash } from "node:crypto";

export const DIGEST_RE = /^[0-9a-f]{16,64}$/;

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** Deterministic canonical JSON: object keys sorted, no insignificant whitespace. */
export function canonical(value: Json): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new CanaryError("E_INPUT", "non-finite number");
    return JSON.stringify(Number(value.toFixed(12)));
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k]!)).join(",") + "}";
}

export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function digestOf(value: Json): string {
  return sha256(canonical(value));
}

export type ErrorCode =
  | "E_INPUT"
  | "E_ORIGIN"
  | "E_IDENTIFIER_SHAPE"
  | "E_SEED"
  | "E_LIMIT"
  | "E_STORE";

/**
 * Errors never carry caller values. `detail` is a fixed vocabulary phrase chosen by this
 * package, never interpolated from input (SPEC §7: "Errors never echo the offending value").
 */
export class CanaryError extends Error {
  readonly code: ErrorCode;
  readonly field: string;
  constructor(code: ErrorCode, detail: string, field = "") {
    super(`${code}: ${detail}`);
    this.code = code;
    this.field = field;
    this.name = "CanaryError";
  }
  toJSON() {
    return { error: this.code, detail: this.message.slice(this.code.length + 2), field: this.field };
  }
}

export function requireId(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 200) {
    throw new CanaryError("E_INPUT", "expected identifier", field);
  }
  return value;
}

export function requireInt(value: unknown, field: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new CanaryError("E_INPUT", `expected integer in [${min},${max}]`, field);
  }
  return value;
}
