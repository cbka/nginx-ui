package security_center

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func remoteService(t *testing.T, endpoint string) *Service {
	t.Helper()
	s := testService(t)
	s.Config.ControlURL = endpoint
	s.Config.ControlTokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(s.Config.ControlTokenFile, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return s
}
func remoteStatus(w http.ResponseWriter, enabled bool) {
	_ = json.NewEncoder(w).Encode(SharingStatus{Configured: true, Enabled: &enabled, Editable: true, RuntimeVerified: false, Message: "ok"})
}
func TestRemoteSharingReadWriteAndBearer(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/sharing" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("wrong endpoint/auth")
		}
		enabled := false
		if r.Method == http.MethodPut {
			var p struct {
				Enabled bool `json:"enabled"`
			}
			if json.NewDecoder(r.Body).Decode(&p) != nil {
				t.Error("invalid request")
			}
			enabled = p.Enabled
		} else if r.Method != http.MethodGet {
			t.Error("wrong method")
		}
		remoteStatus(w, enabled)
	}))
	defer server.Close()
	s := remoteService(t, server.URL)
	v := s.Sharing()
	if !v.Configured || v.Enabled == nil || *v.Enabled || v.RuntimeVerified {
		t.Fatal("wrong read status", v)
	}
	if err := s.SetSharing(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestRemoteSharingRejectsResponsesAndDoesNotLeak(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"redirect", 302, "secret"}, {"unauthorized", 401, "test-token"}, {"oversize", 200, strings.Repeat("x", 65537)}, {"invalid", 200, "{}"}, {"wrongtype", 200, `{"configured":true,"editable":true,"runtime_verified":false,"enabled":"false"}`}, {"unconfirmed", 200, `{"configured":true,"editable":true,"runtime_verified":false,"enabled":false}`}} {
		t.Run(tc.name, func(t *testing.T) {
			redirected := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			s := remoteService(t, server.URL)
			err := s.SetSharing(context.Background(), true)
			if err == nil || strings.Contains(err.Error(), "test-token") || redirected {
				t.Fatal("unsafe response accepted", err)
			}
		})
	}
}
func TestRemoteSharingInvalidOperatorConfigAndCancellation(t *testing.T) {
	for _, endpoint := range []string{"file:///tmp/control", "http://user:pass@localhost", "http://localhost/?q=x", "http://localhost/#x", "http://localhost/base", "http://localhost/?"} {
		s := remoteService(t, endpoint)
		if s.SetSharing(context.Background(), true) == nil {
			t.Fatal("accepted", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { remoteStatus(w, false) }))
	defer server.Close()
	s := remoteService(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.SetSharing(ctx, true) == nil {
		t.Fatal("ignored cancellation")
	}
	s.Config.ControlTokenFile = "relative"
	if s.SetSharing(context.Background(), true) == nil {
		t.Fatal("relative token path")
	}
}
func TestRemoteSharingUnknownDoesNotBecomeFalseOrFallBackLocal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"configured":true,"editable":false,"runtime_verified":false,"enabled":null}`))
	}))
	defer server.Close()
	s := remoteService(t, server.URL)
	v := s.Sharing()
	if !v.Configured || v.Enabled != nil || v.Editable {
		t.Fatal(v)
	}
	s.Config.ControlTokenFile = "/missing-control-token"
	v = s.Sharing()
	if v.Configured || v.Enabled != nil || v.Editable {
		t.Fatal("failed remote must stay unknown", v)
	}
}
func TestRemoteSharingProjectedTokenAndInvalidTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { remoteStatus(w, true) }))
	defer server.Close()
	s := remoteService(t, server.URL)
	link := filepath.Join(t.TempDir(), "projected-token")
	if err := os.Symlink(s.Config.ControlTokenFile, link); err != nil {
		t.Fatal(err)
	}
	s.Config.ControlTokenFile = link
	if err := s.SetSharing(context.Background(), true); err != nil {
		t.Fatal("projected token rejected", err)
	}
	for _, token := range []string{"", "bearer\r\nInjected: true", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(s.Config.ControlTokenFile, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		if s.SetSharing(context.Background(), true) == nil {
			t.Fatal("invalid token accepted")
		}
	}
}
