package stream

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/0xJacky/Nginx-UI/model"
	appsettings "github.com/0xJacky/Nginx-UI/settings"
	"github.com/stretchr/testify/require"
)

func TestReplicatedSaveSkipsAlreadyAppliedBatchButPreservesStagedChanges(t *testing.T) {
	confDir, _ := setupStreamMutationTest(t)
	name := "example.com"
	path := filepath.Join(confDir, "streams-available", name)
	old := "server { listen 8080; proxy_pass 127.0.0.1:9000; }\n"
	changed := "server { listen 8081; proxy_pass 127.0.0.1:9000; }\n"
	require.NoError(t, os.WriteFile(path, []byte(old), 0644))
	require.NoError(t, os.Symlink(path, filepath.Join(confDir, "streams-enabled", name)))
	marker := filepath.Join(t.TempDir(), "reloads")
	appsettings.NginxSettings.ReloadCmd = fmt.Sprintf("printf x >> %q", marker)
	req := httptest.NewRequest(http.MethodPost, "/api/streams/example.com", nil)
	req.Header.Set(nodeauth.ReplicatedFromHeader, `"22222222-2222-4222-8222-222222222222"`)
	ctx := nodeauth.WithPrincipal(req, &nodeauth.Principal{AuthMethod: model.NodeAuthMethodLegacy}).Context()
	tx := &config.FileTransaction{}
	require.NoError(t, tx.Write(path, []byte(old), 0644))
	require.NoError(t, tx.TestAndReload())
	require.NoError(t, Save(ctx, name, old, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e := os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "x", string(b), "metadata save after batch must not create another worker generation")
	require.NoError(t, Save(ctx, name, changed, true, nil, model.PostSyncActionNone))
	require.NoError(t, Save(ctx, name, changed, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e = os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "xx", string(b), "identical staged contents still need application")
	require.NoError(t, Save(ctx, name, changed, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e = os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "xx", string(b))
	require.NoError(t, Save(context.Background(), name, changed, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e = os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "xxx", string(b), "manual apply preserves explicit reload")
	// A staged include/config change invalidates every site's applied proof.
	require.NoError(t, config.WriteFile(filepath.Join(confDir, "staged.conf"), []byte("# staged dependency\n"), 0644))
	require.NoError(t, Save(ctx, name, changed, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e = os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "xxxx", string(b))
	// External edits to file content are detected even though they bypass WriteFile.
	external := "server { listen 8082; proxy_pass 127.0.0.1:9000; }\n"
	require.NoError(t, os.WriteFile(path, []byte(external), 0644))
	require.NoError(t, Save(ctx, name, external, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e = os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "xxxxx", string(b))
	appsettings.NginxSettings.ReloadCmd = "false"
	require.Error(t, Save(ctx, name, "server { listen 8083; proxy_pass 127.0.0.1:9000; }\n", true, nil, model.PostSyncActionReloadNginx))
	appsettings.NginxSettings.ReloadCmd = "true"
	appsettings.NginxSettings.TestConfigCmd = "false"
	require.Error(t, Save(ctx, name, external, true, nil, model.PostSyncActionReloadNginx), "failed reload/rollback must not leave applied proof")

}

// A fresh process must never assume disk contents are already in the workers.
func TestReplicatedSaveWithoutAppliedProofStillReloads(t *testing.T) {
	confDir, _ := setupStreamMutationTest(t)
	name := "fresh.example.com"
	path := filepath.Join(confDir, "streams-available", name)
	content := "server { listen 8080; proxy_pass 127.0.0.1:9000; }\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	require.NoError(t, os.Symlink(path, filepath.Join(confDir, "streams-enabled", name)))
	req := httptest.NewRequest(http.MethodPost, "/api/streams/"+name, nil)
	req.Header.Set(nodeauth.ReplicatedFromHeader, `"22222222-2222-4222-8222-222222222222"`)
	ctx := nodeauth.WithPrincipal(req, &nodeauth.Principal{AuthMethod: model.NodeAuthMethodLegacy}).Context()
	marker := filepath.Join(t.TempDir(), "reloads")
	appsettings.NginxSettings.ReloadCmd = fmt.Sprintf("printf x >> %q", marker)
	require.NoError(t, Save(ctx, name, content, true, nil, model.PostSyncActionReloadNginx))
	WaitForSync()
	b, e := os.ReadFile(marker)
	require.NoError(t, e)
	require.Equal(t, "x", string(b))
	appsettings.NginxSettings.TestConfigCmd = "false"
	require.Error(t, Save(ctx, name, "server { listen 8081; proxy_pass 127.0.0.1:9000; }\n", true, nil, model.PostSyncActionReloadNginx))
	data, e := os.ReadFile(path)
	require.NoError(t, e)
	require.Equal(t, content, string(data))
	// Rollback invalidates proof; a retry cannot skip validation because an old
	// successful apply once happened for these bytes.
	require.Error(t, Save(ctx, name, content, true, nil, model.PostSyncActionReloadNginx))
}
