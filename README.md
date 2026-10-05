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
