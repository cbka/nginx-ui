package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClusterSyncRejectsUnsafeNamesAndPayloads(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../x", "a/b", "a\\b", "x\x00"} {
		require.Error(t, ValidateClusterSiteParams(protocol.HostClusterSiteSyncParams{Name: name, Payload: json.RawMessage(`{}`)}), name)
	}
	for _, payload := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`{`), json.RawMessage(`[]`)} {
		require.Error(t, ValidateClusterSiteParams(protocol.HostClusterSiteSyncParams{Name: "demo.conf", Payload: payload}))
	}
	require.NoError(t, ValidateClusterSiteParams(protocol.HostClusterSiteSyncParams{Name: "demo.conf", Payload: json.RawMessage(`{"revision":1}`)}))
}

type clusterFakeBackend struct {
	fakeHostBackend
	calls int
}

func (f *clusterFakeBackend) ClusterSiteSync(_ context.Context, _ string, p protocol.HostClusterSiteSyncParams) (protocol.HostClusterSiteSyncResult, error) {
	f.calls++
	return protocol.HostClusterSiteSyncResult{Results: []protocol.ClusterPeerResult{{NodeID: 1, Status: "received", Response: json.RawMessage(`{"revision":"5"}`)}}}, nil
}
func TestClusterHostPermissionAndValidation(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			backend := &clusterFakeBackend{}
			var permissions []string
			if allowed {
				permissions = []string{protocol.PermissionClusterSync}
			}
			client := hostPipe(t, permissions, backend)
			var result protocol.HostClusterSiteSyncResult
			err := client.Call(testContext(t), protocol.MethodHostClusterSiteSync, protocol.HostClusterSiteSyncParams{Name: "demo.conf", Payload: json.RawMessage(`{}`)}, &result)
			if !allowed {
				require.Error(t, err)
				require.Zero(t, backend.calls)
				return
			}
			require.NoError(t, err)
			require.Equal(t, 1, backend.calls)
			require.Len(t, result.Results, 1)
			err = client.Call(testContext(t), protocol.MethodHostClusterSiteSync, protocol.HostClusterSiteSyncParams{Name: "../outside", Payload: json.RawMessage(`{}`)}, &result)
			require.Error(t, err)
			require.Equal(t, 1, backend.calls)
		})
	}
}
