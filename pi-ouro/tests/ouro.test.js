import assert from "node:assert/strict";
import test from "node:test";

import { parseQualityResult, splitArgs } from "../extensions/ouro.ts";

test("splitArgs preserves quoted and escaped arguments", () => {
  assert.deepEqual(
    splitArgs(
      String.raw`quality "deep stage" --label 'two words' escaped\ value`,
    ),
    ["quality", "deep stage", "--label", "two words", "escaped value"],
  );
});

test("splitArgs keeps a trailing escape literal", () => {
  assert.deepEqual(splitArgs("argument\\"), ["argument\\"]);
});

test("parseQualityResult accepts a complete quality result", () => {
  const outcome = parseQualityResult({
    stdout: JSON.stringify({
      status: "PASS",
      run_path: ".ouro/runs/001-quality",
      result_path: ".ouro/runs/001-quality/result.json",
      summary: "PASS: all required gates passed",
    }),
    stderr: "",
    code: 0,
  });

  assert.deepEqual(outcome, {
    status: "PASS",
    run_path: ".ouro/runs/001-quality",
    result_path: ".ouro/runs/001-quality/result.json",
    summary: "PASS: all required gates passed",
  });
});

test("parseQualityResult preserves command diagnostics for invalid output", () => {
  assert.deepEqual(
    parseQualityResult({
      stdout: "not json",
      stderr: "quality failed",
      code: 1,
    }),
    {
      error: "quality failed",
      code: 1,
    },
  );
});
