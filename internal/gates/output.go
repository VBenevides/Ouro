package gates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	gateLogLimit     = 32 << 20 // Per stream, after redaction.
	gateLogLineLimit = 1 << 20  // Oversized lines are withheld, never partially redacted.
	gatePreviewLimit = 8 << 10
)

var pendingSecret = regexp.MustCompile(`(?i)(?:(?:authorization|proxy-authorization|token|password|passwd|secret|api[_-]?key|credential|credentials|basic[_-]?auth|client[_-]?secret|header)["']?\s*[:=]|bearer)\s*$`)

// OutputLog describes redacted evidence, not a claim that all raw bytes survived.
// OmittedBytes counts raw bytes withheld by the line limit and redacted bytes
// withheld by the storage limit; redaction replacements are not omissions.
type OutputLog struct {
	Path                string `json:"path"`
	Stream              string `json:"stream"`
	SHA256              string `json:"sha256"`
	BytesSeen           int64  `json:"bytes_seen"`
	BytesWritten        int64  `json:"bytes_written"`
	OmittedBytes        int64  `json:"omitted_bytes"`
	LimitBytes          int    `json:"limit_bytes"`
	LineLimitBytes      int    `json:"line_limit_bytes"`
	PreviewOmittedBytes int64  `json:"preview_omitted_bytes"`
	Complete            bool   `json:"complete"`
	Redacted            bool   `json:"redacted"`
}

type gateOutput struct {
	file         *os.File
	hash         hash.Hash
	gate         Gate
	log          OutputLog
	pending      []byte
	dropping     bool
	err          error
	head, tail   []byte
	previewBytes int64
}

func newGateOutput(directory, root, stream string, gate Gate) (*gateOutput, error) {
	file, err := os.OpenFile(filepath.Join(directory, stream+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create %s gate log: %w", stream, err)
	}
	relative, err := filepath.Rel(root, file.Name())
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &gateOutput{file: file, hash: sha256.New(), gate: gate, log: OutputLog{Path: filepath.ToSlash(relative), Stream: stream, LimitBytes: gateLogLimit, LineLimitBytes: gateLogLineLimit, Complete: true, Redacted: true}}, nil
}

// Write deliberately drains the process even after storage errors. Finish reports
// those errors, allowing the process's real exit code to remain available.
func (output *gateOutput) Write(data []byte) (int, error) {
	size := len(data)
	output.log.BytesSeen += int64(size)
	for len(data) > 0 {
		index := bytes.IndexByte(data, '\n')
		end := len(data)
		if index >= 0 {
			end = index + 1
		}
		part := data[:end]
		data = data[end:]
		if output.dropping {
			output.log.OmittedBytes += int64(len(part))
		} else if len(output.pending)+len(part) > output.log.LineLimitBytes {
			output.log.OmittedBytes += int64(len(output.pending) + len(part))
			output.pending = nil
			output.dropping = true
			output.log.Complete = false
			output.emit("[line omitted: exceeds redaction line limit]\n")
		} else {
			output.pending = append(output.pending, part...)
		}
		if index >= 0 {
			output.flushLine()
		}
	}
	return size, nil
}

func (output *gateOutput) flushLine() {
	if !output.dropping && pendingSecret.Match(output.pending) {
		return
	}
	if !output.dropping {
		output.emit(output.redact(string(output.pending)))
	}
	output.pending = nil
	output.dropping = false
}

func (output *gateOutput) redact(value string) string {
	// Multiline environment values must not leak through line-oriented capture.
	for _, secret := range output.gate.Environment {
		for _, fragment := range strings.Split(secret, "\n") {
			if fragment != "" {
				value = strings.ReplaceAll(value, fragment, "[REDACTED]")
			}
		}
	}
	return redactGateOutput(value, output.gate)
}

func (output *gateOutput) emit(value string) {
	data := []byte(value)
	output.previewBytes += int64(len(data))
	remaining := gatePreviewLimit/2 - len(output.head)
	if remaining > 0 {
		count := min(remaining, len(data))
		output.head = append(output.head, data[:count]...)
		data = data[count:]
	}
	output.tail = append(output.tail, data...)
	if len(output.tail) > gatePreviewLimit/2 {
		output.tail = append([]byte(nil), output.tail[len(output.tail)-gatePreviewLimit/2:]...)
	}
	remaining = output.log.LimitBytes - int(output.log.BytesWritten)
	stored := []byte(value)
	if len(stored) > remaining {
		output.log.Complete = false
		output.log.OmittedBytes += int64(len(stored) - remaining)
		stored = stored[:remaining]
	}
	if output.err != nil {
		output.log.Complete = false
		output.log.OmittedBytes += int64(len(stored))
		return
	}
	count, err := output.file.Write(stored)
	output.log.BytesWritten += int64(count)
	_, _ = output.hash.Write(stored[:count])
	if err != nil {
		output.err = fmt.Errorf("write %s gate log: %w", output.log.Stream, err)
		output.log.Complete = false
		output.log.OmittedBytes += int64(len(stored) - count)
	}
}

func (output *gateOutput) finish() (OutputLog, string, error) {
	if len(output.pending) > 0 {
		output.emit(output.redact(string(output.pending)))
		output.pending = nil
	}
	output.err = errors.Join(output.err, output.file.Sync(), output.file.Close())
	output.log.PreviewOmittedBytes = max(0, output.previewBytes-gatePreviewLimit)
	output.log.SHA256 = "sha256:" + hex.EncodeToString(output.hash.Sum(nil))
	preview := string(output.head)
	if output.previewBytes > gatePreviewLimit {
		preview += "\n… [preview truncated; see log; tail follows]\n"
	}
	preview += string(output.tail)
	return output.log, strings.ToValidUTF8(preview, ""), output.err
}
