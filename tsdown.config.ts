import { readFileSync } from "node:fs";
import { defineConfig } from "tsdown";

const license = readFileSync("LICENSE", "utf8");
const banner = ["/*!", ...license.split("\n").map((line) => ` * ${line}`), " */"].join("\n");

export default defineConfig([
  {
    entry: "src/index.ts",
    // ESM only. CommonJS consumers load it through require(esm) on Node ^20.19 / >=22.12.
    format: ["esm"],
    platform: "neutral",
    dts: true,
    clean: true,
    // One bundled module, as in v2: index.ts and the algorithm modules register
    // the extensions, attributes, algorithms and signature formatters when they run.
    unbundle: false,
    // Keep .js/.d.ts output names (package.json is "type": "module")
    // instead of fixed .mjs/.d.mts extensions.
    fixedExtension: false,
    deps: {
      neverBundle: true,
    },
    exports: {
      legacy: true,
    },
    outputOptions: {
      // Drop TSDoc from the JS output; docs ship in the .d.ts files. Keep
      // @__PURE__ annotations so bundlers can tree-shake.
      comments: { legal: true, annotation: true, jsdoc: false },
    },
    banner,
    outDir: "build",
    tsconfig: "tsconfig.json",
    attw: {
      level: "error",
      profile: "esm-only",
    },
  },
  {
    // Browser bundle for <script> tags (unpkg/jsdelivr): every dependency inlined, exposed as the `x509` global.
    entry: { x509: "src/index.ts" },
    format: ["iife"],
    globalName: "x509",
    platform: "browser",
    dts: false,
    // Runs after the ESM build into the same folder; cleaning would delete it.
    clean: false,
    deps: {
      alwaysBundle: [/.*/],
      onlyBundle: false,
    },
    minify: true,
    outputOptions: {
      // build/x509.js, the path the unpkg and jsdelivr fields have always pointed at.
      entryFileNames: "[name].js",
      comments: { legal: true, annotation: false, jsdoc: false },
    },
    banner,
    outDir: "build",
    tsconfig: "tsconfig.json",
  },
]);
