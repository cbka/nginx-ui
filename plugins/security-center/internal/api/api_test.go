package security_center

import (
	"bytes"
	"encoding/json"
	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
)

func TestPluginRoutesRejectInvalidInputsWithoutCommands(t *testing.T) {
	gin.SetMode(gin.TestMode)
	SetService(center.New(center.Config{Enabled: true, CrowdSecEnabled: true, ModSecurityEnabled: true}))
	r := gin.New()
	InitRouter(r.Group(""))
	for _, v := range []struct{ method, path, body string }{{"POST", "/security-center/crowdsec/decisions", `{"ip":";id","duration":"1h","reason":"test"}`}, {"PUT", "/security-center/templates/invalid..id", `{"name":"test","policy":{}}`}, {"PUT", "/security-center/sites/a.conf", `{broken`}} {
		req := httptest.NewRequest(v.method, v.path, bytes.NewBufferString(v.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("%s returned %d", v.path, w.Code)
		}
	}
}

func TestStatusReportsEventsConfiguredWithoutClaimingVerification(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := service
	t.Cleanup(func() { service = previous })
	for _, tc := range []struct {
		name    string
		enabled bool
		url     string
		want    bool
	}{
		{"missing", true, "", false},
		{"whitespace", true, " \t\n", false},
		{"configured", true, " https://loki.example.invalid ", true},
		{"disabled", false, "https://loki.example.invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_CENTER_LOKI_URL", tc.url)
			SetService(center.New(center.Config{Enabled: tc.enabled}))
			r := gin.New()
			r.GET("/status", Status)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
			var result map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatal("status response failed")
			}
			if result["events_configured"] != tc.want {
				t.Fatal("incorrect events configuration status")
			}
			if _, exists := result["events_verified"]; exists {
				t.Fatal("configuration must not claim event integration verification")
			}
		})
	}
}
