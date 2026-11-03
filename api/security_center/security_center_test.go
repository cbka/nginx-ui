package security_center

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalmcp "github.com/0xJacky/Nginx-UI/internal/mcp"
	"github.com/0xJacky/Nginx-UI/internal/middleware"
	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/gin-gonic/gin"
)

func TestSecurityEndpointsRejectNonInteractivePrincipals(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, principal := range []string{internalmcp.ServiceTokenPrincipalKey, nodeauth.GinPrincipalKey} {
		r := gin.New()
		g := r.Group("/api", func(c *gin.Context) { c.Set(principal, true); c.Next() })
		InitRouter(g)
		for _, route := range r.Routes() {
			w := httptest.NewRecorder()
			path := strings.ReplaceAll(route.Path, ":id", "1")
			r.ServeHTTP(w, httptest.NewRequest(route.Method, path, strings.NewReader(`{}`)))
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s accepted principal: %d", route.Method, path, w.Code)
			}
		}
	}
}
func TestSecurityEndpointsRequireAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	InitRouter(r.Group("/api", middleware.AuthRequired()))
	for _, route := range r.Routes() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(route.Method, strings.ReplaceAll(route.Path, ":id", "1"), strings.NewReader(`{}`)))
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s returned %d", route.Method, route.Path, w.Code)
		}
	}
}
