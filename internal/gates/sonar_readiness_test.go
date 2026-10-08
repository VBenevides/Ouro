package gates

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
)

func TestCheckSonarReadiness(t *testing.T) {
	for _, test := range []struct {
		name, status, auth, want string
		code                     int
	}{
		{name: "ready", status: "UP", auth: `{"valid":true}`},
		{name: "starting", status: "STARTING", want: "endpoint not ready"},
		{name: "invalid token", status: "UP", auth: `{"valid":false}`, want: "incorrect or expired token"},
		{name: "unauthorized", status: "UP", code: http.StatusUnauthorized, want: "authentication check failed"},
		{name: "bad endpoint", code: http.StatusNotFound, want: "endpoint unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("READINESS_TEST_TOKEN", "private-test-token")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				respondToReadinessProbe(t, w, r, test.status, test.auth, test.code)
			}))
			defer server.Close()
			cfg := config.SonarConfig{Mode: "managed-local", URL: server.URL, TokenEnv: "READINESS_TEST_TOKEN"}
			err := CheckSonarReadiness(context.Background(), t.TempDir(), cfg, nil)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want %q, got %v", test.want, err)
			}
			if strings.Contains(err.Error(), "private-test-token") {
				t.Fatal("diagnostic leaked credentials")
			}
		})
	}
}

func respondToReadinessProbe(t *testing.T, w http.ResponseWriter, r *http.Request, status, auth string, code int) {
	t.Helper()
	switch r.URL.Path {
	case "/api/system/status":
		if status == "" {
			w.WriteHeader(code)
			return
		}
		_, _ = fmt.Fprintf(w, `{"status":%q}`, status)
	case "/api/authentication/validate":
		if r.Header.Get("Authorization") == "" {
			t.Error("authentication request lacked credentials")
		}
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		_, _ = fmt.Fprint(w, auth)
	default:
		t.Errorf("unexpected operation: %s", r.URL.Path)
	}
}
