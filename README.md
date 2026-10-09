# Ouro

Release version: **0.1.0**. `VERSION` is embedded in the executable at build time.

Ouro is a deterministic quality-gate runner for an existing Git repository. It
runs configured checks, stores immutable per-run evidence, and returns a
versioned result for the active agent or CI process. Ouro does not launch
models, providers, agent sessions, or nested harnesses.

```sh
go run ./cmd/ouro --help
go run ./cmd/ouro version
go run ./cmd/ouro quality --plan
```

Build Linux and Windows amd64 executables with `./build.sh`; outputs go to
`dist/` by default.

## Initialize and inspect

```sh
go run ./cmd/ouro init
go run ./cmd/ouro doctor
```

`ouro init` detects language components and external tools. It selects the `deep`
quality profile when CodeQL or SonarQube is available; otherwise it selects
`fast`. Use `ouro init --level fast|deep|strict` to choose explicitly. It enables
CodeQL when `codeql` is installed and SonarQube when `SONAR_HOST_URL` and
`SONAR_TOKEN` are available. Use `ouro init --force` to refresh an existing
configuration after these inputs change. Quality configuration is stored in
`.ouro/config.yaml`.

`ouro quality --plan` reports discovered components, selected checks,
requirements, executable readiness, omissions, and unsupported languages. It
does not run project gates or contact external services. A zero exit means local
preflight is complete; it is not a quality pass.

Before every quality execution (`fast`, `deep`, or `strict`), Ouro reports
prerequisite readiness for all selected language-specific and configured checks.
For missing executables, it instructs you to install the tool and run quality
again. Deep and strict runs also make bounded, read-only Sonar endpoint and
authentication requests when Sonar is selected. Unavailable checks are skipped
with diagnostic reasons while available checks continue;
required unavailable checks still block a pass. JSON execution writes readiness
messages to stderr and preserves structured results on stdout. These readiness
checks do not provision services or prove project permissions or a quality pass.

Quality execution handles Ctrl+C and SIGTERM by cancelling active commands and
persisting an incomplete/cancelled result. On Unix, cancellation terminates the
command process group. Before gates start, each run records immutable
`started.json` evidence; this is never a result or a completion claim. A run
without a valid completed result must be treated as incomplete, not passed.
SIGKILL, host failure, or power loss cannot be handled by the parent: descendants
may remain alive and need operator cleanup. On non-Unix platforms, cancellation
currently stops the direct child only; descendant cleanup is not guaranteed.

Configure `quality.keep_artifacts_window` in `.ouro/config.yaml` to control run
artifact retention. It defaults to `5`: when a new run starts, Ouro keeps that
run and the four preceding runs intact. Older completed runs retain only regular
`.json` files in their run root; analyzer databases, coverage files, Markdown
reports, and other artifacts are deleted. `completion.json` preserves completion
and baseline history after the original marker is removed. Set the window to `0`
to disable cleanup. Negative values are invalid. Unfinished runs and newer
concurrent runs are not pruned. Cleanup failures stop execution with an error;
already-removed artifacts cannot be recovered by increasing the window.

CodeQL defaults to a 15-minute overall operation budget, including version
checks, database creation, and analysis of every selected language. Each
individual command also has a 30-minute cap; the earliest parent, operation,
or command deadline wins. Configure `quality.codeql.timeout` explicitly when
a justified workload needs another overall budget. Timeout diagnostics report
the phase and budgets; incomplete analysis never counts as passed.

By default, Ouro creates fresh CodeQL databases. To opt into incremental
overlay analysis, add `incremental: true` under `quality.codeql` in
.ouro/config.yaml:

```yaml
quality:
  codeql:
    incremental: true
```

The first eligible scan creates a reusable base under
.ouro/quality/codeql/overlay-cache. Later scans copy that immutable base and
extract added, modified, and deleted source files. Every run still produces
its own SARIF report, including findings in unchanged code; this is not
diff-only alert filtering. Only completed analyses publish bases (including
analyses with blocking findings). Failed scans never replace a valid base.
Overlay results are not promoted to bases.

This initial implementation supports Go and JavaScript/TypeScript with
CodeQL >= 2.24.2 and Git >= 2.38. Run at the Git repository root with the index
matching the working tree. Ouro never stages files. Unstaged changes,
untracked/ignored files outside .ouro and .agent-work, submodules, tracked
symlinks, unsupported languages, and a busy cache fall back to full analysis.
A clean analysis checkout is recommended, especially for projects with
ignored dependency/build directories. Changes to dependencies or other
non-source tracked files rebuild the base. CLI, Go/Node toolchain versions,
resolved query-packs, languages, source-root, and execution-environment
changes also invalidate compatibility.

Cache decisions and failures are recorded in analyzer stderr. An incremental
analysis failure retries ordinary full analysis at most once within the same
overall timeout; cancellation does not retry. Cache copies reject symlinks
and are limited to 100,000 files/32 GiB. Interrupted cache writers may leave
an overlay-cache/lock directory: confirm that no writer is running before
removing that lock. A busy/interrupted lock never blocks a full scan.

CodeQL's query-compilation caches are separate and can also speed up later
runs. Do not clear shared caches merely to reproduce a slow run. See the
[incremental analysis guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/incremental-analysis)
and [CodeQL command reference](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze).

## Run quality

`fast`, `deep`, and `strict` are cumulative profiles. Without `--stage`, Ouro
uses `quality.profile` or `deep`:

```sh
go run ./cmd/ouro quality --root "$PWD" --json
go run ./cmd/ouro quality --stage fast --json
go run ./cmd/ouro quality --stage strict --run-id release-check --json
```

Every execution creates an immutable folder under `.ouro/runs/<run-id>-.../`.
The JSON command result contains `status`, `run_path`, `result_path`,
per-run report paths, the aggregate `result`, and an actionable `summary`.
Detailed gate output and analyzer reports stay in that run folder. Do not infer
the current result from a mutable shared report.

`PASS` and `PASS_WITH_WARNINGS` exit 0. `FAIL`, `BLOCKED`, `NOT_CONFIGURED`,
`STALE`, `ERROR`, and `CANCELLED` exit 1. Advisory failures remain visible as
warnings and are not clean passes.

## External tools and services

Provisioning and service lifecycle actions are explicit and operator-supplied:

```sh
go run ./cmd/ouro setup --tool NAME --executable COMMAND
go run ./cmd/ouro services --action start --executable COMMAND
go run ./cmd/ouro services --action stop --executable COMMAND
```

Ouro never installs dependencies during a quality run. Keep credentials in the
environment named by the configured token field.

If `govulncheck` reports a Go toolchain mismatch, rebuild it with the active
toolchain using `go install golang.org/x/vuln/cmd/govulncheck@latest`.

If a SonarQube background task fails during indexing, inspect its Compute Engine
and Elasticsearch logs. A flood-stage disk watermark makes indices read-only;
free space below the high watermark and verify the blocks clear before rerunning.
A completed analysis can still fail its quality gate on coverage or findings.

## Codex and Pi packages

The repository ships a Codex plugin and an installable Pi package. Distribute
the compiled executable and package artifacts separately:

```sh
export OURO_BIN=/opt/ouro/bin/ouro
pi install /path/to/pi-ouro
```

The host packages run the same structured `ouro quality --json` command. The
active Codex or Pi session remains the agent and owns source edits, tools,
permissions, and commits. The quality-only packages do not provide lifecycle
workflow hooks, stage guards, approval controls, or nested-agent commands.

For oh-my-pi, install the skill separately because `pi install` does not
populate oh-my-pi's skill directory:

```sh
mkdir -p ~/.omp/agent/skills/ouro-quality
cp /path/to/pi-ouro/skills/ouro-quality/SKILL.md \
  ~/.omp/agent/skills/ouro-quality/SKILL.md
```

Verify the executable before use:

```sh
if [ -n "${OURO_BIN:-}" ]; then test -x "$OURO_BIN"; else command -v ouro; fi
"${OURO_BIN:-ouro}" version
```

## Development checks

```sh
go test ./...
go vet ./...
```
