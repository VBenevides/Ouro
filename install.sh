#!/bin/sh
# Build and install Ouro from the main branch.
#
#   curl -fsSL https://raw.githubusercontent.com/VBenevides/Ouro/main/install.sh | sh
#
# Environment:
#   OURO_REF          branch or tag to build (default: main)
#   OURO_INSTALL_DIR  destination directory (default: ~/.local/bin)
#
# Needs git and go.
set -eu

repo=${OURO_REPO:-https://github.com/VBenevides/Ouro}
ref=${OURO_REF:-main}
install_dir=${OURO_INSTALL_DIR:-"$HOME/.local/bin"}

fail() {
    echo "install: $1" >&2
    exit 1
}

for tool in git go; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required on PATH"
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ouro-install.XXXXXX")
trap 'rm -rf "$tmp"' 0

echo "install: cloning $ref" >&2
git clone --quiet --depth 1 --branch "$ref" "$repo" "$tmp/src" || fail "clone failed"
version=$(tr -d '\r\n' < "$tmp/src/VERSION")

echo "install: building ouro $version" >&2
(cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$tmp/ouro" ./cmd/ouro) || fail "build failed"

mkdir -p -- "$install_dir"
# Stage next to the destination so the final move is atomic.
cp "$tmp/ouro" "$install_dir/.ouro.new.$$" && chmod 0755 "$install_dir/.ouro.new.$$" &&
    mv -f "$install_dir/.ouro.new.$$" "$install_dir/ouro" || fail "could not write $install_dir/ouro"
echo "install: ouro $version installed to $install_dir/ouro" >&2

found=$(command -v ouro 2>/dev/null || true)
if [ "$found" != "$install_dir/ouro" ]; then
    if [ -n "$found" ]; then
        echo "install: warning: $found is found first on PATH and will run instead" >&2
    else
        echo "install: add $install_dir to PATH" >&2
    fi
fi
echo "install: run 'ouro skill' to print the agent skill, and 'ouro update' to update" >&2
