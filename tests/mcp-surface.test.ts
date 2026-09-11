/** The MCP tool surface answers initialize/tools/list/tools/call and reports errors as codes. */
import { expect, test } from "bun:test";
import { CanaryChain } from "../src/canary-chain.js";
import { callTool, TOOLS } from "../src/tools.js";

test("every specified tool is exposed with a schema", () => {
  const names = TOOLS.map((t) => t.name).sort();
  expect(names).toEqual(
    [
      "describe_policy",
      "export_evidence",
      "generate_synthetic_dataset",
      "get_stats",
      "mint_canary",
      "register_honeypot",
      "report_access",
      "reset_state",
      "scan_for_canaries",
    ].sort(),
  );
  for (const t of TOOLS) {
    expect(t.description.length).toBeGreaterThan(20);
    expect(t.inputSchema.type).toBe("object");
  }
});

test("a full tool sequence runs end to end via callTool", async () => {
  const chain = new CanaryChain();
  const gen: any = await callTool(chain, "generate_synthetic_dataset", {
    schema: { fields: [{ name: "a", kind: "string" }] },
    recordCount: 5,
    seed: 3,
  });
  const mint: any = await callTool(chain, "mint_canary", {
    dataset: gen.dataset,
    recordRef: 0,
    recipientLabel: "eval-a",
    method: "unique-key",
  });
  const scan: any = await callTool(chain, "scan_for_canaries", { text: mint.markerValue });
  expect(scan.trips.length).toBe(1);
  const policy: any = await callTool(chain, "describe_policy", {});
  expect(policy.formatVersion).toBe("1.0");
  await expect(callTool(chain, "does_not_exist", {})).rejects.toThrow("E_INPUT");
});

test("JSON-RPC handle() responds to initialize and tools/list", async () => {
  const { handle } = await import("../src/mcp-server.js");
  const writes: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  (process.stdout.write as any) = (chunk: any) => { writes.push(String(chunk)); return true; };
  try {
    await handle({ jsonrpc: "2.0", id: 1, method: "initialize" });
    await handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  } finally {
    process.stdout.write = orig;
  }
  const first = JSON.parse(writes[0]!);
  expect(first.result.serverInfo.name).toBe("shpbl-canary-chain");
  const second = JSON.parse(writes[1]!);
  expect(second.result.tools.length).toBe(9);
});
