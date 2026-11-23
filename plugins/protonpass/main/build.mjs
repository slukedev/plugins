import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const outfile = here("dist/main.js");
const sdkIndex = process.env.ARDIA_PLUGIN_SDK_INDEX ?? here("vendor/plugin-sdk/src/index.ts");

await build({
  entryPoints: [here("src/index.ts")],
  outfile,
  bundle: true,
  format: "iife",
  platform: "neutral",
  target: "es2022",
  legalComments: "none",
  charset: "utf8",
  minifySyntax: true,
  alias: { "@ardia/plugin-sdk": sdkIndex },
  logLevel: "warning",
});

const bundled = readFileSync(outfile, "utf8")
  .replace(/\/\* @__PURE__ \*\/ /g, "")
  .split("\n")
  .filter((line) => !/^\s*\/\/ /.test(line))
  .join("\n");
writeFileSync(outfile, bundled);
