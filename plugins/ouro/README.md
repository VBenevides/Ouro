# Ouro Codex plugin

This directory is a distributable Codex plugin containing the Ouro quality skill
and package metadata. It does not require the Ouro source repository, Go, or a
project checkout.

## Runtime requirement

Install the compiled Ouro executable separately. Put it on `PATH` as `ouro`, or
set an absolute path before starting Codex:

```sh
export OURO_BIN=/opt/ouro/bin/ouro
```

The quality skill fails closed when the executable is unavailable. It does not
fall back to `go run` or search the target project for source code.

## Install

Unpack the plugin artifact to a directory containing `.agents/plugins/marketplace.json`,
`.codex-plugin/plugin.json`, `hooks/`, and `skills/`, then register that directory
and install the plugin:

```sh
codex plugin marketplace add /path/to/unpacked/ouro
codex plugin add ouro@ouro-local
```

The package has no lifecycle workflow hooks. The active Codex session remains the
agent and owns edits, tools, permissions, and commits.

The default skill is `ouro-quality`, installed from
`skills/ouro-quality/SKILL.md`. In Codex, invoke `$ouro-quality` to assess the
project, or explicitly request fixes to authorize the quality → fix → quality
loop. No staged-workflow adapter is required.

## Run quality

In the target project, initialize metadata when needed:

```sh
"${OURO_BIN:-ouro}" init --root "$PWD"
"${OURO_BIN:-ouro}" doctor --root "$PWD"
```

Run the configured quality profile with structured output:

```sh
"${OURO_BIN:-ouro}" quality --root "$PWD" --json
```

The result returns `status`, `run_path`, `result_path`, per-run report paths,
the aggregate result, and a summary. Keep the run path and summary in the
session handoff. Only `PASS` counts as a pass. `PASS_WITH_WARNINGS` exits zero
but requires continued remediation when fixes are authorized; all other
statuses are actionable quality feedback or a concrete blocker.

## Configure SonarQube

Put project settings in
`.ouro/quality/sonarqube/sonar-project.properties` in the target repository.
Ouro loads this file automatically, using the repository-root properties file
only when the `.ouro` file is absent. Relative source, test, and coverage paths
are relative to the repository root.

Configure project identity, sources/tests, inclusions/exclusions, and coverage
report paths there. Keep the server endpoint and token environment in
`.ouro/config.yaml`; do not embed credentials in properties. Ouro keeps scanner
scratch files under `.ouro/quality/sonarqube/scanner/` and forces
`sonar.qualitygate.wait=false` because it polls and reports the result itself.
Rerun the same Ouro quality profile after configuration changes.
