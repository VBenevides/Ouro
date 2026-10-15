# Changelog

All notable changes to Ouro are documented here.

## [0.1.3] - 2026-10-15

### Bugfixes

- Prefer component-local Node executables during prerequisite checks and gate execution, searching ancestor installations within the repository before falling back to global tools. Preserve explicitly configured executable paths and do not retry failing local tools globally; report ESLint and TypeScript global fallback reasons.
- Preserve installed Node package resolution in isolated quality workspaces by privately copying applicable `node_modules` installations. Keep dependency files outside quality-input snapshots and synchronization, and reject dependency links that leave their installation.
- Retain late gate failure diagnostics in redacted, per-stream log artifacts under each run directory, with artifact references in structured results and log paths in reports. Keep bounded previews of both the output prefix and tail instead of discarding the tail.
- Report log completeness, byte counts, omitted bytes, and storage limits separately from preview truncation. Limit durable output to 32 MiB per stream and omit lines exceeding the 1 MiB redaction limit; surface incomplete evidence or persistence failures without losing the original process exit code.
- Preserve existing output-truncation flags when serializing quality receipts.

### Other

- Add regressions for component-local tool precedence, global fallback, broken local installations, isolated ESM imports, and prevention of dependency edits reaching the checkout.
- Add regressions for failure diagnostics beyond the 4 MiB capture limit, artifact hashes and private log permissions, split-write secret redaction, storage limits, and log creation/write failures.

## [0.1.2] - 2026-10-14

### Features

- Add repeatable, comma-separated `ouro quality --item NAME` selection using exact configured gate names, with targeted plans and rejection of unavailable names or stages. A bare `--item` lists all applicable project items without executing gates; `--json` returns an `items` array. Aliases are not supported.

## [0.1.1] - 2026-10-09

### Features

- Report prerequisite readiness before running quality gates, with installation and repair guidance. Check selected Sonar endpoints and authentication through bounded, read-only requests; skip unavailable checks while continuing available checks. Required unavailable checks still block a pass.
- Persist structured prerequisite assessments in quality results, including gate IDs, readiness states, diagnostic codes, and next steps. Keep progress and readiness messages on stderr when using JSON output.
- Show command start, periodic running, and completion messages with elapsed time, remaining deadline budget, and final status, without exposing command arguments or environment values.
- Add opt-in CodeQL incremental overlay caching through `quality.codeql.incremental`. Support Go and JavaScript/TypeScript with CodeQL 2.24.2 or newer and Git 2.38 or newer; reuse compatible immutable bases while still producing complete, per-run SARIF results. Ineligible inputs fall back to full analysis, and failed incremental analysis retries full analysis at most once within the same timeout budget.
- Export affected files, new-code coverage metrics, uncovered lines, and partially covered conditions to Sonar JSON and Markdown reports when the new-code coverage condition fails. Bound collection to 50 files and 100 requests, and mark incomplete exports with warnings.
- Add configurable run-artifact retention through `quality.keep_artifacts_window`, defaulting to the current run plus four preceding runs. Older completed runs retain root JSON evidence and completion history; unfinished and newer concurrent runs are preserved. Set the window to `0` to disable cleanup.

### Bugfixes

- Handle Ctrl+C and SIGTERM by cancelling active quality commands and preserving cancelled or incomplete results. Record immutable `started.json` evidence before execution so abruptly terminated runs are not mistaken for completed runs; Unix cancellation terminates command process groups.
- Isolate prerequisite decisions by gate stage and component so an unavailable check does not suppress a same-name check in another stage.
- Explain CodeQL timeouts with the failed phase, overall operation budget, per-command cap, effective deadline precedence, and rerun guidance. Partial analysis never counts as a pass.
- Respect Git ignore rules during component discovery and quality-input snapshots. Run ordinary gates and CodeQL source extraction from a filtered working copy, and synchronize non-ignored gate edits back to the project.
- Preserve Sonar settings inspection and file-close errors when opening settings fails or the file changes during opening.

### Other

- Add Linux and Windows CI jobs for builds, prerequisite and process regressions, Go static analysis, and JavaScript tests, plus the full Go suite with race detection on Linux.
- Expand regression coverage for readiness, interruption, timeout diagnostics, overlay caching, coverage exports, artifact retention, and ignored-input isolation.
- Document prerequisite checks, cancellation limitations, artifact cleanup, CodeQL timeout budgets, and incremental-cache requirements and recovery.
- Update Ouro quality skills with ignored-path safeguards and disable model-initiated invocation for the Pi and oh-my-pi skill copies.

### Breaking Changes

- Artifact cleanup is now enabled by default: starting a new quality run deletes non-JSON artifacts from older completed runs outside the retention window, including analyzer databases, coverage files, and Markdown reports. Set `quality.keep_artifacts_window: 0` before running quality to preserve all artifacts; increasing the window cannot restore deleted files.
- Gitignored inputs are no longer discovered or included in ordinary gate execution and CodeQL source extraction. Configured custom commands and Sonar properties must also exclude ignored paths.
