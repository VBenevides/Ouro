package ouro

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version returns the release version embedded from VERSION at build time.
func Version() string {
	return strings.TrimSpace(versionFile)
}
