package process

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestCommandProgressReportsTimingAndStops(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	command := Command{Label: "codeql database analyze javascript", Progress: &output, Args: []string{"private-token"}, Environment: map[string]string{"TOKEN": "private-token"}}
	stop := startCommandProgress(ctx, command, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	stop(StatusPass)
	before := output.String()
	time.Sleep(5 * time.Millisecond)
	if output.String() != before {
		t.Fatal("heartbeat continued after completion")
	}
	for _, expected := range []string{"command started: codeql database analyze javascript", "command running:", "command finished:", "elapsed=", "remaining=", "status=PASS"} {
		if !strings.Contains(before, expected) {
			t.Fatalf("missing %q in %s", expected, before)
		}
	}
	if strings.Contains(before, "private-token") {
		t.Fatal("progress exposed arguments or environment")
	}
}

func TestProgressTimingUsesParentDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if !strings.Contains(progressTiming(ctx, time.Now()), "remaining=0s") {
		t.Fatal("expired budget was not clamped to zero")
	}
	if !strings.Contains(progressTiming(context.Background(), time.Now()), "remaining=unbounded") {
		t.Fatal("unbounded context was not identified")
	}
	stop := startCommandProgress(context.Background(), Command{}, time.Millisecond)
	stop(StatusPass)
}
