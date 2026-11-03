package plugin

import (
	internalmcp "github.com/0xJacky/Nginx-UI/internal/mcp"
	"github.com/0xJacky/Nginx-UI/internal/middleware"
	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestPrivilegedHTTPRejectsNodeAndProxyBeforeHandler(t *testing.T) {
	m := setupManager(t)
	manifest := webappManifest("io.example.privileged")
	manifest.Permissions = []string{"http.privileged"}
	installTestPlugin(t, m, manifest, map[string]string{"webapp/main.js": "// test"}, false)
	for _, mode := range []string{"node", "service", "proxy", "no-secure-session"} {
		t.Run(mode, func(t *testing.T) {
			r := gin.New()
			called := false
			r.Use(func(c *gin.Context) {
				if mode == "no-secure-session" {
					c.Set("user", &model.User{EnabledTwoFA: true})
				}
				if mode == "service" {
					c.Set(internalmcp.ServiceTokenPrincipalKey, true)
				}
				if mode == "node" {
					c.Set(nodeauth.GinPrincipalKey, true)
				}
				if mode == "proxy" {
					c.Set("ProxyNodeID", "1")
				}
				c.Next()
			})
			r.GET("/plugins/:id/http/test", privilegedPluginHTTP, whenPrivileged(middleware.RequireInteractiveUser()), whenPrivileged(middleware.RequireSecureSession()), func(c *gin.Context) { called = true; c.Status(200) })
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/plugins/io.example.privileged/http/test", nil))
			require.False(t, called)
			require.GreaterOrEqual(t, w.Code, 400)
		})
	}
}
