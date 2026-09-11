import { CanaryChain } from "../src/canary-chain.js";
export function chainWithDataset(recordCount = 10, seed = 1) {
  const chain = new CanaryChain();
  const { dataset, datasetId } = chain.generateSyntheticDataset({
    schema: { fields: [{ name: "x", kind: "string" }] },
    recordCount,
    seed,
  });
  return { chain, dataset, datasetId };
}
