package security_center

import (
	"bytes"
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
