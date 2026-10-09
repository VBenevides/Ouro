//go:build linux

package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCancelledCommandTerminatesProcessGroup(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan Result, 1)
	go func() {
		finished <- (OSRunner{}).Run(ctx, Command{Executable: "/bin/sh", Args: []string{"-c", "(touch ready; sleep 1; touch survived) & wait"}, Dir: root, Timeout: 5 * time.Second})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	result := <-finished
	if result.Status != StatusCancelled {
		t.Fatalf("cancellation status: %+v", result)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(root, "survived")); !os.IsNotExist(err) {
		t.Fatalf("descendant continued after cancellation: %v", err)
	}
}
