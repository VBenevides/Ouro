//go:build linux

package cli

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestQualitySignalContextHandlesTermination(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestQualitySignalHelper$")
	command.Env = append(os.Environ(), "OURO_SIGNAL_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("signal helper failed: %v: %s", err, output)
	}
}

func TestQualitySignalHelper(t *testing.T) {
	if os.Getenv("OURO_SIGNAL_HELPER") != "1" {
		return
	}
	ctx, stop := qualitySignalContext()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatal(ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("SIGTERM did not cancel quality context")
	}
}
