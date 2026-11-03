package security_center

import (
	"net/http/httptest"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/gin-gonic/gin"
)

func TestReplicaGateRequiresPairedControllerIdentity(t *testing.T) {
	cases := []struct {
		name      string
		principal any
		want      int
	}{{"browser", nil, 403}, {"malformed", true, 403}, {"legacy", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodLegacy, ControllerInstanceID: "source"}, 403}, {"paired missing identity", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired}, 403}, {"paired controller", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired, ControllerInstanceID: "source"}, 204}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.PUT("/replica", func(c *gin.Context) {
				if tc.principal != nil {
					c.Set(nodeauth.GinPrincipalKey, tc.principal)
				}
				c.Next()
			}, requirePairedController, func(c *gin.Context) { c.Status(204) })
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("PUT", "/replica", nil))
			if w.Code != tc.want {
				t.Fatalf("got%d want%d", w.Code, tc.want)
			}
		})
	}
}
