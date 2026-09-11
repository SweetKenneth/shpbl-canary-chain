/**
 * Real-world identifier-shape detection for recipient labels (SPEC §3.2 / §7 / P2).
 *
 * This is a documented, versioned negative corpus, not a claim of universal coverage
 * (SPEC §7: "not claimed to recognize every Unicode confusable or every real-world
 * identifier format"). Because a recipient label is already constrained to
 * `^[A-Za-z0-9_-]{1,64}$` before this check runs, only shapes reachable within that
 * character set are practically detectable here; the remaining classes are listed for
 * `describe_policy` transparency even though most real instances of them (containing `@`,
 * `.`, `:`, or whitespace) are already excluded by the base pattern.
 */

export type IdentifierShapeClass =
  | "email"
  | "url"
  | "hostname"
  | "ipv4"
  | "ipv6"
  | "phone"
  | "iban"
  | "payment-card"
  | "cloud-arn"
  | "cloud-access-key";

export const IDENTIFIER_SHAPE_CLASSES: IdentifierShapeClass[] = [
  "email",
  "url",
  "hostname",
  "ipv4",
  "ipv6",
  "phone",
  "iban",
  "payment-card",
  "cloud-arn",
  "cloud-access-key",
];

const CHECKS: Array<[IdentifierShapeClass, (v: string) => boolean]> = [
  ["email", (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)],
  ["url", (v) => /^[a-z][a-z0-9+.-]*:\/\//i.test(v)],
  ["hostname", (v) => /^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v)],
  ["ipv4", (v) => /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(v)],
  ["ipv6", (v) => /^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$/.test(v) && v.includes(":")],
  ["phone", (v) => /^\+?\d{7,15}$/.test(v)],
  ["iban", (v) => /^[A-Z]{2}\d{2}[A-Za-z0-9]{10,30}$/.test(v)],
  ["payment-card", (v) => isPaymentCardShape(v)],
  ["cloud-arn", (v) => /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:.+$/.test(v)],
  ["cloud-access-key", (v) => /^(AKIA|ASIA)[0-9A-Z]{16}$/.test(v)],
];

function isPaymentCardShape(v: string): boolean {
  const digits = v.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  return luhnValid(digits);
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Returns the first matching shape class, or null if the value matches none. */
export function matchIdentifierShape(value: string): IdentifierShapeClass | null {
  for (const [cls, test] of CHECKS) {
    if (test(value)) return cls;
  }
  return null;
}
