import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  ExecResult,
  ExtensionAPI,
  ExtensionCommandContext,
} from "@earendil-works/pi-coding-agent";

const extensionRoot = dirname(fileURLToPath(import.meta.url));
const qualityStages: Record<string, true> = {
  fast: true,
  deep: true,
  strict: true,
};

type QualityCommandResult = {
  schema_version?: number;
  run_id?: string;
  run_path: string;
  result_path: string;
  quality_report_path?: string;
  markdown_report_path?: string;
  status: string;
  summary: string;
  result?: Record<string, unknown>;
};

type QualityOutcome = QualityCommandResult | { error: string; code?: number };

type SplitState = {
  current: string;
  quote: string;
  escaped: boolean;
};

function consumeEscapedCharacter(char: string, state: SplitState): boolean {
  if (!state.escaped) return false;
  state.current += char;
  state.escaped = false;
  return true;
}

function consumeQuotedCharacter(char: string, state: SplitState): boolean {
  if (!state.quote) return false;
  if (char === state.quote) state.quote = "";
  else state.current += char;
  return true;
}

function consumeWhitespace(
  char: string,
  args: string[],
  state: SplitState,
): boolean {
  if (!/\s/.test(char)) return false;
  if (state.current) {
    args.push(state.current);
    state.current = "";
  }
  return true;
}

function splitArgs(input: string): string[] {
  const args: string[] = [];
  const state: SplitState = { current: "", quote: "", escaped: false };
  for (const char of input.trim()) {
    if (consumeEscapedCharacter(char, state)) continue;
    if (char === "\\" && state.quote !== "'") {
      state.escaped = true;
      continue;
    }
    if (consumeQuotedCharacter(char, state)) continue;
    if (char === "'" || char === '"') {
      state.quote = char;
      continue;
    }
    if (consumeWhitespace(char, args, state)) continue;
    state.current += char;
  }
  if (state.escaped) state.current += "\\";
  if (state.current) args.push(state.current);
  return args;
}

function parseQualityResult(result: ExecResult): QualityOutcome {
  try {
    const parsed: unknown = JSON.parse(result.stdout);
    if (typeof parsed !== "object" || parsed === null)
      throw new Error("result is not an object");
    const value = parsed as Partial<QualityCommandResult>;
    if (typeof value.status !== "string" || !value.status)
      throw new Error("status is missing");
    if (typeof value.run_path !== "string" || !value.run_path)
      throw new Error("run_path is missing");
    if (typeof value.result_path !== "string" || !value.result_path)
      throw new Error("result_path is missing");
    if (typeof value.summary !== "string" || !value.summary)
      throw new Error("summary is missing");
    return value as QualityCommandResult;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      error:
        result.stderr.trim() ||
        `Ouro returned an invalid quality result: ${detail}`,
      code: result.code,
    };
  }
}

async function runQuality(
  pi: ExtensionAPI,
  ctx: { cwd: string; signal?: AbortSignal },
  stage?: string,
): Promise<QualityOutcome> {
  const args = ["quality", "--root", resolve(ctx.cwd), "--json"];
  if (stage) args.push("--stage", stage);
  try {
    const result = await pi.exec(process.env.OURO_BIN ?? "ouro", args, {
      cwd: ctx.cwd,
      signal: ctx.signal,
      timeout: 300_000,
    });
    return parseQualityResult(result);
  } catch (error) {
    return {
      error: `Ouro executable is unavailable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function outcomeMessage(outcome: QualityOutcome) {
  if ("error" in outcome) return outcome.error;
  const reports = [outcome.quality_report_path, outcome.markdown_report_path]
    .filter(Boolean)
    .join(", ");
  return [
    `Ouro quality: ${outcome.status}`,
    `Summary: ${outcome.summary}`,
    `Run: ${outcome.run_path}`,
    `Result: ${outcome.result_path}`,
    reports ? `Reports: ${reports}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function outcomeLevel(outcome: QualityOutcome): "info" | "warning" | "error" {
  if ("error" in outcome) return "error";
  return outcome.status === "PASS" || outcome.status === "PASS_WITH_WARNINGS"
    ? "info"
    : "warning";
}

async function handleCommand(
  pi: ExtensionAPI,
  input: string,
  ctx: ExtensionCommandContext,
) {
  const args = splitArgs(input);
  if (args[0] === "help") {
    ctx.ui.notify("Usage: /ouro [quality] [fast|deep|strict]", "info");
    return;
  }
  const stage = args[0] === "quality" ? args[1] : args[0];
  if (stage && !qualityStages[stage]) {
    ctx.ui.notify("Usage: /ouro [quality] [fast|deep|strict]", "warning");
    return;
  }
  if (args.length > (args[0] === "quality" ? 2 : 1)) {
    ctx.ui.notify("Usage: /ouro [quality] [fast|deep|strict]", "warning");
    return;
  }
  const outcome = await runQuality(pi, ctx, stage);
  const message = outcomeMessage(outcome);
  ctx.ui.notify(message, outcomeLevel(outcome));
  pi.sendMessage(
    {
      customType: "ouro-quality",
      content: message,
      display: true,
      details: outcome,
    },
    { triggerTurn: true },
  );
}

export default function ouroExtension(pi: ExtensionAPI) {
  pi.registerCommand("ouro", {
    description: "Run the Ouro quality gate",
    handler: async (input, ctx) => {
      await handleCommand(pi, input, ctx);
    },
  });
  pi.on("resources_discover", () => ({
    skillPaths: [join(extensionRoot, "..", "skills")],
  }));
}

export { parseQualityResult, runQuality, splitArgs };
