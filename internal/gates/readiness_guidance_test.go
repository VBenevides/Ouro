package gates

import (
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/process"
)

func TestUnavailableExecutableRuntimeGuidance(t *testing.T) {
	status, detail := classifyGateResult(process.Result{Status: process.StatusUnavailable, Err: "executable not found"}, Gate{Command: []string{"/tools/ruff", "check", "."}})
	if status != Skipped {
		t.Fatalf("unexpected status: %s", status)
	}
	for _, required := range []string{"executable not found", "Install ruff", "PATH", "run Ouro quality again"} {
		if !strings.Contains(detail, required) {
			t.Fatalf("missing %q in %q", required, detail)
		}
	}
}
