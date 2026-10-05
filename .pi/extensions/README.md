# Ouro Pi extension

The installable package is `pi-ouro/`. It keeps Pi as the active agent and
runs the Ouro quality gate from the current session. It registers `/ouro`,
which executes the versioned JSON quality command, and discovers the bundled
quality skill.

Distribute the package with the compiled `ouro` executable; agents do not need
access to the Ouro source repository:

```sh
export OURO_BIN=/opt/ouro/bin/ouro
pi install /path/to/pi-ouro
```

In the target repository, initialize metadata before running quality:

```sh
"${OURO_BIN:-ouro}" init
"${OURO_BIN:-ouro}" doctor
```

For a one-off development load, use `pi -e /path/to/pi-ouro`. From the active
Pi session, run:

```text
/ouro
/ouro quality fast
```

The extension returns the quality status, summary, and immutable run path. It
does not register workflow lifecycle controls, stage guards, approval prompts,
or the `ouro_workflow` tool. The extension fails closed when the executable is
unavailable; it does not build or search a source checkout.
