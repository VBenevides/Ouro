package gates

import (
	"errors"
	"fmt"
	"os"

	"github.com/VBenevides/Ouro/internal/process"
)

func openGateLogs(directory, root string, gate Gate, command *process.Command) ([]*gateOutput, error) {
	if directory == "" {
		return nil, nil
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create gate log directory: %w", err)
	}
	private, err := os.MkdirTemp(directory, "gate-")
	if err != nil {
		return nil, fmt.Errorf("create private gate log directory: %w", err)
	}
	stdout, err := newGateOutput(private, root, "stdout", gate)
	if err != nil {
		return nil, err
	}
	stderr, err := newGateOutput(private, root, "stderr", gate)
	if err != nil {
		return nil, errors.Join(err, stdout.file.Close())
	}
	command.StdoutWriter, command.StderrWriter = stdout, stderr
	return []*gateOutput{stdout, stderr}, nil
}

// Runner implementations may return output without using streaming sinks.
func (output *gateOutput) finishCaptured(data []byte, truncated bool) (OutputLog, string, error) {
	if output.log.BytesSeen == 0 {
		_, _ = output.Write(data)
		if truncated {
			output.log.Complete = false
		}
	}
	return output.finish()
}

func finishGateLogs(outputs []*gateOutput, captured process.Result, result *Result, logErr error) {
	incomplete := false
	for index, output := range outputs {
		data, truncated := captured.Stdout, captured.StdoutTruncated
		if index == 1 {
			data, truncated = captured.Stderr, captured.StderrTruncated
		}
		log, preview, err := output.finishCaptured(data, truncated)
		if index == 0 {
			result.Stdout = preview
		} else {
			result.Stderr = preview
		}
		result.OutputTruncated = result.OutputTruncated || output.previewBytes > gatePreviewLimit
		if err != nil {
			logErr = errors.Join(logErr, fmt.Errorf("persist %s gate log: %w", log.Stream, err))
			continue
		}
		result.OutputLogs = append(result.OutputLogs, log)
		incomplete = incomplete || !log.Complete
	}
	if logErr != nil {
		result.Status, result.Fresh = Error, false
		result.Detail += "; output evidence persistence failed: " + redact(logErr.Error())
	} else if incomplete {
		result.Status, result.Fresh = Error, false
		result.Detail += "; output evidence incomplete: log byte or redaction line limit exceeded (see output_logs)"
	} else if len(outputs) == 0 && result.OutputTruncated {
		result.Status, result.Detail, result.Fresh = Error, "gate output was truncated; durable logs unavailable", false
	}
}
