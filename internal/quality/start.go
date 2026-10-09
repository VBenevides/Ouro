package quality

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteRunStart records durable intent before gates run. This is not a result
// or a completion marker: after abrupt termination it remains incomplete evidence.
func WriteRunStart(root, runID string, started time.Time, plan Plan) error {
	canonical, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	if err := VerifyRunReservation(canonical, runID); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	path := filepath.Join(QualityRunDirectory(canonical, runID), "started.json")
	if err := verifyQualityRunPath(canonical, path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		RunID     string    `json:"run_id"`
		StartedAt time.Time `json:"started_at"`
		State     string    `json:"state"`
		Plan      Plan      `json:"plan"`
	}{runID, started.UTC(), "incomplete-until-result", plan}, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create quality start evidence: %w", err)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}
