package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	plugin "github.com/0xJacky/Nginx-UI/internal/plugin"
	"github.com/0xJacky/Nginx-UI/internal/plugin/jsonrpc"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type replicaFake struct {
	info     plugin.Info
	calls    int
	received protocol.ClusterSiteApplyParams
	err      error
}

func (f *replicaFake) Get(string) (*plugin.Info, error) { return &f.info, nil }
func (f *replicaFake) Acquire(context.Context, string) (jsonrpc.Caller, func(), error) {
	return f, func() {}, nil
}
func (f *replicaFake) Notify(context.Context, string, any) error { return nil }
func (f *replicaFake) Call(_ context.Context, method string, params any, result any) error {
	f.calls++
	if method != protocol.MethodClusterSiteApply {
		return errors.New("wrong method")
	}
	f.received = params.(protocol.ClusterSiteApplyParams)
	if f.err != nil {
		return f.err
	}
	*result.(*json.RawMessage) = json.RawMessage(`{"status":"applied","revision":"5"}`)
	return nil
}
func TestReplicaAuthenticationAndDispatch(t *testing.T) {
	cases := []struct {
		name      string
		principal any
		enabled   bool
		permitted bool
		body      string
		want      int
	}{
		{"browser", nil, true, true, `{}`, 403},
		{"legacy", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodLegacy, ControllerInstanceID: "controller"}, true, true, `{}`, 403},
		{"missing identity", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired}, true, true, `{}`, 403},
		{"disabled", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired, ControllerInstanceID: "controller"}, false, true, `{}`, 404},
		{"no permission", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired, ControllerInstanceID: "controller"}, true, false, `{}`, 404},
		{"malformed", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired, ControllerInstanceID: "controller"}, true, true, `{`, 400},
		{"success", &nodeauth.Principal{AuthMethod: model.NodeAuthMethodPaired, ControllerInstanceID: "controller"}, true, true, `{"controller_instance_id":"spoof","revision":"5"}`, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &replicaFake{info: plugin.Info{Enabled: tc.enabled}}
			if tc.permitted {
				f.info.Permissions = []string{protocol.PermissionClusterSync}
			}
			r := gin.New()
			r.PUT("/plugins/:id/replica/sites/:name", func(c *gin.Context) {
				if tc.principal != nil {
					c.Set(nodeauth.GinPrincipalKey, tc.principal)
				}
				c.Next()
			}, requireReplicaController, func(c *gin.Context) { servePluginReplica(f, c) })
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("PUT", "/plugins/io.test.security/replica/sites/demo.conf", strings.NewReader(tc.body)))
			require.Equal(t, tc.want, w.Code)
			if tc.want == 200 {
				require.Equal(t, 1, f.calls)
				require.Equal(t, "controller", f.received.ControllerInstanceID)
				require.Equal(t, "demo.conf", f.received.Name)
			} else {
				require.Zero(t, f.calls)
			}
		})
	}
}
