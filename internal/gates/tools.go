package gates

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func VerifyManagedArtifact(path, expectedSHA256 string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(expectedSHA256) == "" {
		return errors.New("managed artifact path and SHA-256 are required")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expectedSHA256) {
		return fmt.Errorf("managed artifact hash mismatch: got %s, want %s", actual, expectedSHA256)
	}
	return nil
}
