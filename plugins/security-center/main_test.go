package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRequiresPerProcessSecretAndReadyLifecycle(t *testing.T) {
	a := &application{failure: "initializing"}
	called := false
	h := a.guarded(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }), "test-process-secret")
	for _, v := range []struct {
		secret string
		ready  bool
		status int
	}{{"", false, 403}, {"wrong", true, 403}, {"test-process-secret", false, 503}, {"test-process-secret", true, 200}} {
		a.ready = v.ready
		r := httptest.NewRequest("GET", "/security-center/status", nil)
		r.Header.Set("Nginx-UI-Plugin-Secret", v.secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != v.status {
			t.Fatalf("got %d wanted %d", w.Code, v.status)
		}
	}
	if !called {
		t.Fatal("authorized handler never called")
	}
}
func TestActivationWaitsForInitializationAndRejectsFailure(t *testing.T) {
	a := &application{initializedDone: make(chan struct{}), failure: "validation failed"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.activate(ctx, nil); err == nil {
		t.Fatal("activation did not wait for initialization")
	}
	close(a.initializedDone)
	if _, err := a.activate(context.Background(), nil); err == nil {
		t.Fatal("failed initialization reported success")
	}
	a.ready = true
	if _, err := a.activate(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPluginLifecycleEnablesManagementWithoutEnablingEngines(t *testing.T) {
	t.Setenv("SECURITY_CENTER_MODSECURITY_ENABLED", "false")
	t.Setenv("SECURITY_CENTER_CROWDSEC_ENABLED", "false")
	for _, legacy := range []string{"", "false", "true"} {
		t.Setenv("SECURITY_CENTER_ENABLED", legacy)
		c := activePluginConfig()
		if !c.Enabled {
			t.Fatal("host-enabled plugin must not depend on legacy enabled environment flag")
		}
		if c.ModSecurityEnabled || c.CrowdSecEnabled {
			t.Fatal("plugin activation must not enable security engines")
		}
	}
	t.Setenv("SECURITY_CENTER_MODSECURITY_ENABLED", "true")
	c := activePluginConfig()
	if !c.ModSecurityEnabled || c.CrowdSecEnabled {
		t.Fatal("independent operator engine configuration must be retained")
	}
}
