/** Tool surface shared by the MCP server and the skill. Nine tools, SPEC §3. */
import { CanaryChain } from "./canary-chain.js";
import { CanaryError, Json } from "./canonical.js";

export const TOOLS = [
  {
    name: "generate_synthetic_dataset",
    description: "Generate a package-fabricated synthetic dataset from an explicit schema and a fixed seed. Reads no file, network, environment, or clipboard.",
    inputSchema: {
      type: "object",
      required: ["schema", "recordCount", "seed"],
      properties: {
        schema: { type: "object", required: ["fields"], properties: { fields: { type: "array" } } },
        recordCount: { type: "integer" },
        seed: { type: "integer" },
      },
    },
  },
  {
    name: "mint_canary",
    description: "Embed an opaque canary marker into a record of a package-generated synthetic dataset. There is no public path that accepts raw or external data.",
    inputSchema: {
      type: "object",
      required: ["dataset", "recordRef", "recipientLabel", "method"],
      properties: {
        dataset: { type: "object" },
        recordRef: { type: "integer" },
        recipientLabel: { type: "string" },
        method: { type: "string", enum: ["field-value", "record-append", "unique-key"] },
      },
    },
  },
  {
    name: "scan_for_canaries",
    description: "Scan operator-supplied text for previously minted canary markers. Never opens a file, fetches a URL, or subscribes to a stream.",
    inputSchema: {
      type: "object",
      required: ["text"],
      properties: { text: {}, maxChars: { type: "integer" } },
    },
  },
  {
    name: "register_honeypot",
    description: "Register a honeypot against a record of a package-generated synthetic dataset.",
    inputSchema: {
      type: "object",
      required: ["dataset", "recordRef", "label"],
      properties: { dataset: { type: "object" }, recordRef: { type: "integer" }, label: { type: "string" } },
    },
  },
  {
    name: "report_access",
    description: "Record that a registered honeypot was accessed.",
    inputSchema: {
      type: "object",
      required: ["honeypotId"],
      properties: { honeypotId: { type: "string" }, accessedAt: { type: "string" } },
    },
  },
  {
    name: "get_stats",
    description: "Return digest-only counts of minted canaries and trips, per dataset and per recipient label.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "reset_state",
    description: "Clear the current session's own records. Prior exported evidence is unaffected.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "export_evidence",
    description: "Export the payload-free, hash-linked evidence chain produced so far.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "describe_policy",
    description: "Return input limits, clock-skew tolerance, identifier-shape classes, and format versions.",
    inputSchema: { type: "object", properties: {} },
  },
] as const;

export async function callTool(chain: CanaryChain, name: string, args: any): Promise<Json> {
  switch (name) {
    case "generate_synthetic_dataset":
      return chain.generateSyntheticDataset(args) as unknown as Json;
    case "mint_canary": {
      const out = chain.mintCanary(args);
      return out as unknown as Json;
    }
    case "scan_for_canaries":
      return (await chain.scanForCanaries(args)) as unknown as Json;
    case "register_honeypot":
      return chain.registerHoneypot(args) as unknown as Json;
    case "report_access":
      return (await chain.reportAccess(args)) as unknown as Json;
    case "get_stats":
      return chain.getStats() as unknown as Json;
    case "reset_state":
      return chain.resetState() as unknown as Json;
    case "export_evidence":
      return chain.exportEvidence() as unknown as Json;
    case "describe_policy":
      return chain.describePolicy() as unknown as Json;
    default:
      throw new CanaryError("E_INPUT", "unknown tool", "name");
  }
}
