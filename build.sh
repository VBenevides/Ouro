#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
version="$(tr -d '\r\n' < VERSION)"

if [[ -z "$version" ]]; then
	printf 'VERSION is empty\n' >&2
	exit 1
fi

mkdir -p "$output_dir"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -ldflags='-s -w' \
	-o "$output_dir/ouro-${version}-linux-amd64" ./cmd/ouro

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	go build -trimpath -ldflags='-s -w' \
	-o "$output_dir/ouro-${version}-windows-amd64.exe" ./cmd/ouro

printf 'Built %s and %s\n' \
	"$output_dir/ouro-${version}-linux-amd64" \
	"$output_dir/ouro-${version}-windows-amd64.exe"
