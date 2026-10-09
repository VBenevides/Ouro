---
name: ouro-quality
description: Run and remediate the Ouro quality gate in the current Pi or oh-my-pi session.
disable-model-invocation: true
---

# Ouro quality

The active agent owns source edits, tools, permissions, and commits. Ouro only
runs the deterministic quality gate and returns evidence.

## Available flows

- **Initialize:** If configuration is absent, run `ouro init --root "$PWD"`.
  Use `--level fast|deep|strict` only when a specific profile is requested.
  Do not refresh existing configuration or change gate policy just to obtain a pass.
- **Inspect readiness:** Run `ouro quality --root "$PWD" --plan --json`.
  Use `ouro doctor --root "$PWD" --json` for configuration and tool diagnostics.
  Neither command proves that project gates pass.
- **Assess:** Run quality, inspect that run's artifacts, and report the result.
  An assessment request alone does not authorize source changes or commits.
- **Remediate and reverify:** When asked to fix failures, validate findings against
  the source, make the smallest correct changes, then run quality again.
  Preserve the requested profile, gates, thresholds, and exclusions.
- **Repair prerequisites:** Missing tools or service failures are distinct from
  code findings. Use `ouro tools`, `ouro setup`, or `ouro services` as applicable;
  inspect `ouro help COMMAND` for arguments. Provisioning and destructive or
  service-lifecycle actions still require the host's permissions. Do not report
  unavailable analyzers as passed. After repair, run quality again.

`PASS_WITH_WARNINGS` does not count as a pass, even though Ouro exits zero.
Only `PASS`, together with inspection of the per-gate results, satisfies a
request to make the quality gate pass. When remediation is authorized, the
agent MUST continue investigating and fixing warnings, then run Ouro quality
again until the result is `PASS` or a concrete blocker prevents further work.
Do not stop at `PASS_WITH_WARNINGS`, suppress warnings, weaken gates, or retry
unchanged failures indefinitely. Assessment-only requests still do not authorize
edits: report the warnings and state explicitly that the result is not a pass.

## Quality → fix → quality

1. Verify the local executable and initialize only if configuration is absent.
2. Run the configured quality profile, or the explicitly requested `--stage`,
   with `--json`.
3. Read `status` and inspect the returned run's per-gate results and diagnostics.
4. For an assessment-only request, report the result without changing files.
   When remediation is authorized, fix the underlying code, configuration, tool,
   or service issue with the smallest justified change.
5. Run Ouro quality again with the same profile in a new run directory.
6. Continue authorized remediation until `PASS`; if a concrete blocker remains,
   report the exact failing gate, attempted repair, and missing prerequisite.
   Never describe a blocked or warning-bearing result as a pass.

## Gitignored files

Gitignored files and directories (for example `.venv/`, `node_modules/`, or
local reference projects) are outside the quality gates. They MUST NOT be
discovered as components, formatted, checked, tested, scanned, or audited, and
this includes everything inside an ignored directory.

Ouro builds its component list and runs gates from the files Git does not
ignore. Before running Ouro, confirm that any custom gate, command, or Sonar
properties file the project configures also excludes ignored paths. If the
configured gates cannot enforce this boundary, report the blocker instead of
running them. Never remove ignore rules, force-include ignored files, or
direct a tool at an ignored path to obtain a pass.

## Verification boundary

To check whether source, configuration, tool, or service changes worked, rerun
`"${OURO_BIN:-ouro}" quality --root "$PWD" --json`, keeping the same requested
`--stage` when applicable. Each rerun must create a new run directory.

Do not bypass Ouro by invoking underlying test, lint, coverage, scanner, or audit
commands directly, or querying analyzer/service endpoints to verify a fix. Do not
manually submit scans or poll background tasks. Ouro owns gate execution and
collection of their results.

Reading source and logs for diagnosis is allowed; it is not verification.
Read-only readiness commands are not substitutes for a completed quality run.
If Ouro's artifacts omit necessary diagnostics, report that evidence gap rather
than constructing a parallel verification path. Only a completed new Ouro run
can establish the result after a change; previous artifacts describe the prior state.

## Configure SonarQube

When configuration changes are authorized, the agent MAY create or edit
`.ouro/quality/sonarqube/sonar-project.properties` in the target repository.
Use it to configure the project key, organization, sources, tests,
inclusions/exclusions, and Go or JavaScript/TypeScript coverage report paths.
Do not change thresholds, exclusions, or gate policy merely to obtain a pass.

Ouro automatically loads this file; no separate scanner invocation is needed.
It takes precedence over a repository-root `sonar-project.properties`; the
files are not merged. Relative paths are relative to the repository root.
Scanner scratch data is kept separately in `.ouro/quality/sonarqube/scanner/`.

Keep server and credential settings in `.ouro/config.yaml` and the configured
token environment, not in the properties file. Ouro owns scanner working
directory and branch/pull-request policy and forces `sonar.qualitygate.wait=false`
because it polls and reports the quality-gate result itself. After changing
properties, run a new Ouro quality execution with the same requested profile;
configuration changes alone do not prove a pass.

## Runtime prerequisite

The target host must provide the compiled `ouro` executable as `ouro` on `PATH`
or through `OURO_BIN=/absolute/path/to/ouro`. Never build, search, clone, or
install the source repository as a runtime fallback.

If `.ouro/config.yaml` is absent, initialize the target project:

```sh
"${OURO_BIN:-ouro}" init --root "$PWD"
```

Do not overwrite an invalid existing configuration. Report the error and stop.

## Artifact boundary

All Ouro artifacts MUST remain under `.ouro/`. Each quality execution creates
an immutable `.ouro/runs/<run-id>-.../` folder containing that run's result,
summary, and reports. Do not write Ouro artifacts to `.agent-work/`, `/tmp`, or
the repository root.

## Run and consume quality

Verify the executable, then run structured quality output:

```sh
if [ -n "${OURO_BIN:-}" ]; then test -x "$OURO_BIN"; else command -v ouro; fi
"${OURO_BIN:-ouro}" version
"${OURO_BIN:-ouro}" quality --root "$PWD" --json
```

Use `--stage fast`, `--stage deep`, or `--stage strict` when a specific profile
is required. Use `--plan --json` to inspect readiness without running gates.

Consume the JSON fields `status`, `run_path`, `result_path`, the aggregate
`result`, and `summary`. Inspect the returned `run_path` for detailed gate
results. Do not use a mutable shared report path or infer a pass from free-form
output.

`PASS` and `PASS_WITH_WARNINGS` exit zero, but only `PASS` counts as a pass.
`FAIL`, `BLOCKED`, `NOT_CONFIGURED`, `STALE`, `ERROR`, and `CANCELLED` exit
nonzero. Inspect the structured status, not just the exit code. Warnings require
continued remediation when authorized, not a success claim. Preserve the run
path and summary in the handoff.
