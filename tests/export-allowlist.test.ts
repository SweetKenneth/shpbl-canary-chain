/** P7: adding a new public export must fail this check. */
import { expect, test } from "bun:test";

test("index.ts exports exactly the reviewed surface", async () => {
  const mod = await import("../src/index.js");
  const names = Object.keys(mod).sort();
  expect(names).toEqual(
    [
      "CanaryChain",
      "CanaryError",
      "EvidenceChain",
      "GENESIS_DIGEST",
      "IDENTIFIER_SHAPE_CLASSES",
      "TOOLS",
      "callTool",
      "canonical",
      "digestOf",
      "generateSyntheticDataset",
      "isSyntheticDataset",
      "matchIdentifierShape",
      "sha256",
      "verifyChain",
    ].sort(),
  );
});
