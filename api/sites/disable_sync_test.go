package sites

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDisableMaintenanceReplicatesOnlyFinalDisabledState(t *testing.T) {
	name := "maintenance.example.com"
	db := setupManagedSiteAPITest(t, name, "", false)
	var mu sync.Mutex
	var requests []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer peer.Close()
	node := model.Node{Name: "peer", URL: peer.URL, Token: "test", AuthMethod: model.NodeAuthMethodLegacy}
	require.NoError(t, db.Create(&node).Error)
	setTestPeerCredential(t, db, &node)
	require.NoError(t, db.Model(&model.Site{}).Where("path = ?", sitePath(t, name)).Update("sync_node_ids", fmt.Sprintf("[%d]", node.ID)).Error)
	maintenancePath, err := site.ResolveEnabledMaintenancePath(name)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(maintenancePath, []byte(managedSiteAPIContent), 0644))
	require.NoError(t, disableSiteByName(context.Background(), name))
	site.WaitForSync()
	mu.Lock()
	require.Equal(t, []string{"POST /api/sites/" + name + "/disable"}, requests)
	mu.Unlock()
	enabledPath, err := site.ResolveEnabledPath(name)
	require.NoError(t, err)
	_, err = os.Lstat(enabledPath)
	require.True(t, os.IsNotExist(err))
	// Retry must reconcile remote peers even though the controller is disabled.
	require.NoError(t, disableSiteByName(context.Background(), name))
	mu.Lock()
	require.Len(t, requests, 2)
	mu.Unlock()
}

func TestDeletePeerFailurePreservesControllerForRetry(t *testing.T) {
	name := "delete-retry.example.com"
	db := setupManagedSiteAPITest(t, name, "", false)
	var mu sync.Mutex
	fail := true
	requests := 0
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if fail {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"site is enabled"}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer peer.Close()
	node := model.Node{Name: "peer", URL: peer.URL, Token: "test", AuthMethod: model.NodeAuthMethodLegacy}
	require.NoError(t, db.Create(&node).Error)
	setTestPeerCredential(t, db, &node)
	require.NoError(t, db.Model(&model.Site{}).Where("path = ?", sitePath(t, name)).Update("sync_node_ids", fmt.Sprintf("[%d]", node.ID)).Error)
	require.ErrorContains(t, site.Delete(context.Background(), name), "HTTP 409")
	var count int64
	require.NoError(t, db.Model(&model.Site{}).Where("path = ?", sitePath(t, name)).Count(&count).Error)
	require.EqualValues(t, 1, count)
	_, err := os.Stat(sitePath(t, name))
	require.NoError(t, err)
	mu.Lock()
	fail = false
	mu.Unlock()
	require.NoError(t, site.Delete(context.Background(), name))
	require.NoError(t, db.Model(&model.Site{}).Where("path = ?", sitePath(t, name)).Count(&count).Error)
	require.Zero(t, count)
	mu.Lock()
	require.Equal(t, 2, requests)
	mu.Unlock()
}

func setTestPeerCredential(t *testing.T, db *gorm.DB, node *model.Node) {
	old := settings.CryptoSettings.Secret
	oldID := settings.NodeSettings.InstanceID
	settings.NodeSettings.InstanceID = "22222222-2222-4222-8222-222222222222"
	settings.CryptoSettings.Secret = "test-site-sync-secret-long-enough"
	t.Cleanup(func() { settings.CryptoSettings.Secret = old; settings.NodeSettings.InstanceID = oldID })
	secret, err := nodeauth.EncryptPrivateCredential(nodeauth.LegacyCredentialPurpose(node.ID), []byte("test-secret"))
	require.NoError(t, err)
	require.NoError(t, db.Model(node).Update("encrypted_legacy_secret", secret).Error)
}
