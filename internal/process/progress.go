package process

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Progress writes are serialized because gates may share a writer in parallel.
var progressMutex sync.Mutex

func startCommandProgress(ctx context.Context, command Command, interval time.Duration) func(Status) {
	if command.Progress == nil {
		return func(Status) {
			// No writer means progress is disabled; there is no ticker to stop.
		}
	}
	label := strings.TrimSpace(command.Label)
	if label == "" {
		label = filepath.Base(command.Executable)
	}
	started := time.Now()
	writeCommandProgress(command.Progress, "ouro: command started: %s; %s\n", label, progressTiming(ctx, started))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				writeCommandProgress(command.Progress, "ouro: command running: %s; %s\n", label, progressTiming(ctx, started))
			}
		}
	}()
	return func(status Status) {
		close(stop)
		<-done
		writeCommandProgress(command.Progress, "ouro: command finished: %s; status=%s; %s\n", label, status, progressTiming(ctx, started))
	}
}

func progressTiming(ctx context.Context, started time.Time) string {
	elapsed := time.Since(started).Round(time.Millisecond)
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return fmt.Sprintf("elapsed=%s; remaining=unbounded", elapsed)
	}
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("elapsed=%s; remaining=%s", elapsed, remaining.Round(time.Millisecond))
}

func writeCommandProgress(writer io.Writer, format string, values ...any) {
	progressMutex.Lock()
	defer progressMutex.Unlock()
	_, _ = fmt.Fprintf(writer, format, values...)
}
