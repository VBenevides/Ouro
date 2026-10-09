package gates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/VBenevides/Ouro/internal/config"
)

// CheckSonarReadiness makes bounded, read-only requests; it never provisions a
// project or submits an analysis. Redirects are rejected to protect credentials.
func CheckSonarReadiness(ctx context.Context, root string, cfg config.SonarConfig, client HTTPDoer) error {
	resolved, err := ResolveSonarConfig(root, cfg)
	if err != nil {
		return err
	}
	cfg = resolved
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "remote"
	}
	if err := validateSonarEndpoint(mode, cfg.URL); err != nil {
		return err
	}
	token := os.Getenv(cfg.TokenEnv)
	if cfg.TokenEnv != "" && strings.TrimSpace(token) == "" {
		return fmt.Errorf("sonar token environment variable is empty: %s", cfg.TokenEnv)
	}
	if err := requireTrustedSonarCredential(mode, cfg.URL, token); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	base := strings.TrimRight(cfg.URL, "/")
	if mode != "cloud" {
		var status struct {
			Status string `json:"status"`
		}
		if err := sonarGETJSON(ctx, client, base+"/api/system/status", "", &status); err != nil {
			return sonarReadinessError{cause: err, message: "sonar endpoint unavailable: " + redactSonarDiagnostic(err.Error(), token, cfg.URL)}
		}
		if status.Status != "UP" {
			return fmt.Errorf("sonar endpoint not ready (status %q)", boundedSonarField(status.Status))
		}
	}
	var authentication struct {
		Valid bool `json:"valid"`
	}
	if err := sonarGETJSON(ctx, client, base+"/api/authentication/validate", token, &authentication); err != nil {
		return sonarReadinessError{cause: err, message: "sonar authentication check failed: " + redactSonarDiagnostic(err.Error(), token, cfg.URL)}
	}
	if !authentication.Valid {
		return errors.New("sonar authentication rejected: incorrect or expired token")
	}
	return nil
}

type sonarReadinessError struct {
	cause   error
	message string
}

func (e sonarReadinessError) Error() string { return e.message }
func (e sonarReadinessError) Unwrap() error { return e.cause }
