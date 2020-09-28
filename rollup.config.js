import fs from "fs";
import resolve from "@rollup/plugin-node-resolve";
import { getBabelOutputPlugin } from "@rollup/plugin-babel";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "rollup-plugin-typescript2";
import { terser } from "rollup-plugin-terser";

const license = fs.readFileSync("LICENSE", {encoding: "utf-8"});

// eslint-disable-next-line @typescript-eslint/no-var-requires, no-undef
const pkg = require("./package.json");

const banner = [
  "/*!",
  ...license.split("\n").map(o => ` * ${o}`),
  " */",
].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies)
  .concat(["events"]);

// main
const main = {
  input,
  plugins: [
    typescript({
      check: true,
      clean: true,
      tsconfigOverride: {
        compilerOptions: {
          module: "ES2015",
        }
      },
    }),
  ],
  external,
  output: [
    {
      banner,
      file: pkg.main,
      format: "cjs",
    },
    {
      banner,
      file: pkg.module,
      format: "es",
    },
  ],
};

const browser = [
  {
    input,
    plugins: [
      resolve({
        mainFields: ["esnext", "module", "main"],
        preferBuiltins: true,
      }),
      commonjs(),
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "es2015",
          }
        }
      }),
    ],
    output: [
      {
        banner,
        file: pkg.browser,
        format: "iife",
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  chrome: "60"
                },
              }],
            ],
          }),
          terser(),
        ],
        name: "x509"
      }
    ]
  },
];

export default [
  main,
  ...browser,
];