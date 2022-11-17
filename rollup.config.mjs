import fs from "fs";
import path from "path";
import url from "url";
import resolve from "@rollup/plugin-node-resolve";
import { getBabelOutputPlugin } from "@rollup/plugin-babel";
import commonjs from "@rollup/plugin-commonjs";
import dts from "rollup-plugin-dts";
import typescript from "rollup-plugin-typescript2";
import { terser } from "rollup-plugin-terser";
import pkg from "./package.json" assert { type: "json" };

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const license = fs.readFileSync("LICENSE", { encoding: "utf-8" });

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
        file: pkg.unpkg,
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

const types = {
  input,
  external: [...external],
  plugins: [
    dts({
      // eslint-disable-next-line no-undef
      tsconfig: path.resolve(__dirname, "./tsconfig.json"),
      compilerOptions: {
        removeComments: false,
      }
    })
  ],
  output: [
    {
      banner,
      file: pkg.types,
    }
  ]
};

export default [
  main,
  ...browser,
  types,
];