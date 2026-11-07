package site

import (
	"context"
	"errors"
	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/testdb"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	appsettings "github.com/0xJacky/Nginx-UI/settings"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type deleteTestEnv struct {
	db           *gorm.DB
	syncedNames  []string
	availableDir string
	enabledDir   string
}

func setupDeleteTest(t *testing.T) *deleteTestEnv {
	t.Helper()

	confDir := t.TempDir()
	env := &deleteTestEnv{
		availableDir: filepath.Join(confDir, "sites-available"),
		enabledDir:   filepath.Join(confDir, "sites-enabled"),
	}
	for _, dir := range []string{env.availableDir, env.enabledDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create %s: %v", dir, err)
		}
	}

	originalConfigDir := appsettings.NginxSettings.ConfigDir
	appsettings.NginxSettings.ConfigDir = confDir
	t.Cleanup(func() {
		appsettings.NginxSettings.ConfigDir = originalConfigDir
	})

	database, err := gorm.Open(sqlite.Open(testdb.DSN(t)), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	if err := database.AutoMigrate(&model.Namespace{}, &model.Site{}, &model.Cert{}); err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}
	model.Use(database)
	query.SetDefault(database)
	env.db = database

	originalSyncDelete := syncDelete
	syncDelete = func(_ context.Context, name string) error {
		env.syncedNames = append(env.syncedNames, name)
		return nil
	}
	t.Cleanup(func() {
		syncDelete = originalSyncDelete
	})

	return env
}

// addSite writes the site file and its database record, returning the record.
func (env *deleteTestEnv) addSite(t *testing.T, name string, namespaceID uint64, remoteEnabled bool) *model.Site {
	t.Helper()

	availablePath := filepath.Join(env.availableDir, name)
	if err := os.WriteFile(availablePath, []byte("server {}\n"), 0o644); err != nil {
		t.Fatalf("failed to write site file: %v", err)
	}

	siteModel := &model.Site{
		Path:          availablePath,
		NamespaceID:   namespaceID,
		SyncNodeIDs:   []uint64{1, 2},
		RemoteEnabled: remoteEnabled,
	}
	if err := env.db.Create(siteModel).Error; err != nil {
		t.Fatalf("failed to create site record: %v", err)
	}
	return siteModel
}

func (env *deleteTestEnv) assertRefusedWithoutSideEffects(t *testing.T, name string, siteModel *model.Site, err, want error) {
	t.Helper()

	if !errors.Is(err, want) {
		t.Fatalf("Delete(context.Background(), %q) error = %v, want %v", name, err, want)
	}
	if len(env.syncedNames) != 0 {
		t.Fatalf("refused delete dispatched sync delete for %v", env.syncedNames)
	}

	var got model.Site
	if err := env.db.Unscoped().First(&got, siteModel.ID).Error; err != nil {
		t.Fatalf("refused delete removed the site record: %v", err)
	}
	if got.NamespaceID != siteModel.NamespaceID || len(got.SyncNodeIDs) != len(siteModel.SyncNodeIDs) {
		t.Fatalf("refused delete changed the site record: got %+v, want %+v", got, siteModel)
	}
	if _, err := os.Stat(siteModel.Path); err != nil {
		t.Fatalf("refused delete removed the site file: %v", err)
	}
}

func TestDeleteEnabledSiteKeepsRecordAndSkipsSync(t *testing.T) {
	env := setupDeleteTest(t)

	const name = "enabled.conf"
	siteModel := env.addSite(t, name, 0, false)
	if err := os.Symlink(siteModel.Path, filepath.Join(env.enabledDir, name)); err != nil {
		t.Fatalf("failed to enable site: %v", err)
	}

	err := Delete(context.Background(), name)
	env.assertRefusedWithoutSideEffects(t, name, siteModel, err, ErrSiteIsEnabled)
}

func TestDeleteSiteInMaintenanceKeepsRecordAndSkipsSync(t *testing.T) {
	env := setupDeleteTest(t)

	const name = "maintenance.conf"
	siteModel := env.addSite(t, name, 0, false)
	maintenancePath := filepath.Join(env.enabledDir, name+MaintenanceSuffix)
	if err := os.WriteFile(maintenancePath, []byte("server {}\n"), 0o644); err != nil {
		t.Fatalf("failed to write maintenance file: %v", err)
	}

	err := Delete(context.Background(), name)
	env.assertRefusedWithoutSideEffects(t, name, siteModel, err, ErrSiteIsInMaintenance)
}

func TestDeleteRemoteEnabledSiteKeepsRecordAndSkipsSync(t *testing.T) {
	env := setupDeleteTest(t)

	namespace := &model.Namespace{DeployMode: model.DeployModeRemote}
	if err := env.db.Create(namespace).Error; err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}

	const name = "remote.conf"
	siteModel := env.addSite(t, name, namespace.ID, true)

	err := Delete(context.Background(), name)
	env.assertRefusedWithoutSideEffects(t, name, siteModel, err, ErrSiteIsEnabled)
}

func TestDeleteMissingSiteKeepsRecordAndSkipsSync(t *testing.T) {
	env := setupDeleteTest(t)

	const name = "missing.conf"
	siteModel := env.addSite(t, name, 0, false)
	if err := os.Remove(siteModel.Path); err != nil {
		t.Fatalf("failed to remove site file: %v", err)
	}

	err := Delete(context.Background(), name)
	if !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("Delete(context.Background(), %q) error = %v, want %v", name, err, ErrSiteNotFound)
	}
	if len(env.syncedNames) != 0 {
		t.Fatalf("refused delete dispatched sync delete for %v", env.syncedNames)
	}
	if err := env.db.Unscoped().First(&model.Site{}, siteModel.ID).Error; err != nil {
		t.Fatalf("refused delete removed the site record: %v", err)
	}
}

func TestDeleteDisabledSiteRemovesEverything(t *testing.T) {
	env := setupDeleteTest(t)

	const name = "disabled.conf"
	siteModel := env.addSite(t, name, 0, false)

	if err := Delete(context.Background(), name); err != nil {
		t.Fatalf("Delete(context.Background(), %q) error = %v", name, err)
	}
	if len(env.syncedNames) != 1 || env.syncedNames[0] != name {
		t.Fatalf("sync delete calls = %v, want [%s]", env.syncedNames, name)
	}
	err := env.db.Unscoped().First(&model.Site{}, siteModel.ID).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("site record lookup error = %v, want record not found", err)
	}
	if _, err := os.Stat(siteModel.Path); !os.IsNotExist(err) {
		t.Fatalf("site file stat error = %v, want not exist", err)
	}
}

func TestDeleteRemoteFailureKeepsRetryMetadata(t *testing.T) {
	env := setupDeleteTest(t)
	name := "retry.example.com"
	record := env.addSite(t, name, 0, false)
	failure := errors.New("peer is still enabled")
	syncDelete = func(context.Context, string) error { return failure }
	err := Delete(context.Background(), name)
	env.assertRefusedWithoutSideEffects(t, name, record, err, failure)
}

func TestReplicatedDeleteAlreadyAbsentIsIdempotent(t *testing.T) {
	setupDeleteTest(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/sites/missing.example.com", nil)
	req.Header.Set(nodeauth.ReplicatedFromHeader, `"22222222-2222-4222-8222-222222222222"`)
	ctx := nodeauth.WithPrincipal(req, &nodeauth.Principal{AuthMethod: model.NodeAuthMethodLegacy}).Context()
	require.NoError(t, Delete(ctx, "missing.example.com"))
	require.ErrorIs(t, Delete(context.Background(), "missing.example.com"), ErrSiteNotFound)
}

func TestDeleteCleansOnlyOrphanGeneratedMaintenanceMetadata(t *testing.T) {
	for _, kind := range []string{"orphan", "real-config", "managed", "remote-enabled", "dangling-link", "remote-failure"} {
		t.Run(kind, func(t *testing.T) {
			env := setupDeleteTest(t)
			name := "cleanup.example.com"
			env.addSite(t, name, 0, false)
			generatedPath := filepath.Join(env.availableDir, name+MaintenanceSuffix)
			generated := model.Site{Path: generatedPath}
			if kind == "remote-enabled" {
				generated.RemoteEnabled = true
			}
			if kind == "managed" {
				generated.ManagedBy = "ingress:protected"
			}
			require.NoError(t, env.db.Create(&generated).Error)
			if kind == "real-config" {
				require.NoError(t, os.WriteFile(generatedPath, []byte("server {}"), 0644))
			}
			if kind == "dangling-link" {
				require.NoError(t, os.Symlink(generatedPath, filepath.Join(env.enabledDir, name+MaintenanceSuffix)))
			}
			if kind == "remote-failure" {
				syncDelete = func(context.Context, string) error { return errors.New("peer unavailable") }
			}
			err := Delete(context.Background(), name)
			if kind == "remote-failure" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			var count int64
			require.NoError(t, env.db.Unscoped().Model(&model.Site{}).Where("path = ?", generatedPath).Count(&count).Error)
			if kind == "orphan" {
				require.Zero(t, count)
			} else {
				require.EqualValues(t, 1, count)
			}
		})
	}
}
