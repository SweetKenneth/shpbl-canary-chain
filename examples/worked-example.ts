/** SPEC §9 worked example, end to end. Run: bun examples/worked-example.ts */
import { CanaryChain } from "../src/index.js";

async function run() {
  const chain = new CanaryChain();
  const { dataset, datasetId } = chain.generateSyntheticDataset({
    schema: { fields: [{ name: "subject", kind: "string" }, { name: "priority", kind: "integer", min: 1, max: 5 }] },
    recordCount: 500,
    seed: 42,
  });
  console.log("dataset:", datasetId);

  const mint = chain.mintCanary({ dataset, recordRef: 118, recipientLabel: "internal-eval-b", method: "unique-key" });
  console.log("minted:", mint.canaryId, "marker (handed to caller once):", mint.markerValue);

  const transcript = `Agent transcript excerpt referencing ${mint.markerValue} unexpectedly.`;
  const scan = await chain.scanForCanaries({ text: transcript });
  console.log("scan:", JSON.stringify(scan));
  console.log("stats:", JSON.stringify(chain.getStats()));
  const evidence = chain.exportEvidence();
  console.log("evidence entries:", evidence.entries.length, "chain valid:", evidence.valid);
}
run();
