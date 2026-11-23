import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));

await build({
  entryPoints: [here("support/entry.ts")],
  outfile: here(".build/subject.mjs"),
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  alias: { "@ardia/plugin-sdk": here("support/sdk.ts") },
  logLevel: "warning",
});
