import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const sdk = (path) => here(`vendor/plugin-sdk/src/${path}`);

export const sdkAliases = {
  "@ardia/plugin-sdk/jsx-runtime": sdk("jsxRuntime.ts"),
  "@ardia/plugin-sdk/jsx-dev-runtime": sdk("jsxRuntime.ts"),
  "@ardia/plugin-sdk/testing": sdk("credentialsTesting.ts"),
  "@ardia/plugin-sdk": sdk("index.ts"),
};

export async function bundleMain(outfile = here("dist/main.js")) {
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
    alias: sdkAliases,
    logLevel: "warning",
  });
  const bundled = readFileSync(outfile, "utf8")
    .replace(/\/\* @__PURE__ \*\/ /g, "")
    .split("\n")
    .filter((line) => !/^\s*\/\/ /.test(line))
    .join("\n");
  writeFileSync(outfile, bundled);
}

export async function bundleForTests(entry, outfile) {
  await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    alias: sdkAliases,
    logLevel: "warning",
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await bundleMain();
