export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    ignores: ["node_modules/**"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: {
      "no-constant-condition": "error",
      "no-duplicate-case": "error",
      "no-dupe-keys": "error",
      "no-undef": "error",
      "no-unreachable": "error",
      "no-unused-vars": "error",
      "no-useless-escape": "error",
      "use-isnan": "error",
      "valid-typeof": "error",
    },
  },
  {
    ignores: ["extensions/**/*.ts"],
  },
];
