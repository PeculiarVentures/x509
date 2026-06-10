import tseslint from "typescript-eslint";
import baseConfig from "@peculiar/eslint-config-base";

export default tseslint.config(
  ...baseConfig,
  {
    settings: {
      "import/resolver": {
        typescript: { project: "./tsconfig.json" },
        node: true,
      },
    },
    rules: {
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/member-delimiter-style": "off",
      "@stylistic/quotes": ["error", "double"],
      "@typescript-eslint/naming-convention": "off",
      "@typescript-eslint/unified-signatures": "off",
      "@typescript-eslint/no-extraneous-class": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@stylistic/padding-line-between-statements": "off",
    },
  },
  {
    ignores: [
      "build/**/*",
      "website/**/*",
    ],
  },
);
