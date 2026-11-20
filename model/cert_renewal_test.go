package model

import (
	"github.com/0xJacky/Nginx-UI/settings"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestGetAutoCertListMaintenancePolicy(t *testing.T) {
	tx := setupUserPasskeyTestDB(t)
	require.NoError(t, tx.AutoMigrate(&Cert{}))
	old := settings.NginxSettings.ConfigDir
	dir := t.TempDir()
	settings.NginxSettings.ConfigDir = dir
	t.Cleanup(func() { settings.NginxSettings.ConfigDir = old })
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sites-enabled"), 0700))
	for _, item := range []struct {
		name   string
		mode   int
		suffix string
		want   bool
	}{
		{"maintenance", AutoCertEnabled, "_nginx_ui_maintenance", true},
		{"paused", AutoCertPaused, "_nginx_ui_maintenance", false},
		{"disabled", AutoCertDisabled, "_nginx_ui_maintenance", false},
		{"normal", AutoCertEnabled, "", true},
		{"absent", AutoCertEnabled, "missing", false},
	} {
		require.NoError(t, tx.Create(&Cert{Name: item.name, Filename: item.name, AutoCert: item.mode, ChallengeMethod: CertChallengeMethodHTTP01}).Error)
		if item.suffix != "missing" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "sites-enabled", item.name+item.suffix), []byte("server {}"), 0600))
		}
	}
	got := GetAutoCertList()
	names := map[string]bool{}
	for _, c := range got {
		names[c.Filename] = true
	}
	require.Equal(t, map[string]bool{"maintenance": true, "normal": true}, names)
}
