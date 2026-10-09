package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func qualitySignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
