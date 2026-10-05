# Ouro Pi package

This directory is a distributable Pi package containing the Ouro quality
extension and skill. It does not require the Ouro source repository, Go, or a
project checkout.

## Runtime requirement

Install the compiled Ouro executable separately. Put it on `PATH` as `ouro`, or
set an absolute path before starting Pi:

```sh
export OURO_BIN=/opt/ouro/bin/ouro
```

The extension fails closed when the executable is unavailable. It does not fall
back to `go run` or search the target project for source code.

## Install

```sh
pi install /path/to/unpacked/pi-ouro
```

For a skill-only oh-my-pi host, copy the bundled skill separately:

```sh
mkdir -p ~/.omp/agent/skills/ouro-quality
cp /path/to/unpacked/pi-ouro/skills/ouro-quality/SKILL.md \
  ~/.omp/agent/skills/ouro-quality/SKILL.md
```

The package exposes a quality command from the active Pi session. It does not
start agents, manage workflow stages, or provide approval controls.

## Run quality

In the target project:

```sh
"${OURO_BIN:-ouro}" init --root "$PWD"
"${OURO_BIN:-ouro}" doctor --root "$PWD"
```

Use `ouro init --level fast|deep|strict` to override automatic profile selection.

Run the gate from Pi with `/ouro` or `/ouro quality [fast|deep|strict]`. The
command executes `ouro quality --json`, reports the status, summary, and run
folder, and sends the structured result to the active session.
