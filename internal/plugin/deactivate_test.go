package plugin

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExplicitDeactivateMustSucceedBeforeDisableOrUninstall(t *testing.T) {
	usePluginProcesses(t, "deactivate-denied")
	m := newTestManager(t)
	ctx := context.Background()
	m.Start(ctx)
	manifest := pluginManifest("official.deactivate")
	manifest.Permissions = append(manifest.Permissions, "lifecycle.deactivate")
	_, err := m.Install(ctx, buildTestPackage(t, manifest, nil), InstallOptions{Enable: true})
	require.NoError(t, err)
	_, err = m.Disable(ctx, manifest.ID)
	require.ErrorContains(t, err, "did not confirm")
	info, err := m.Get(manifest.ID)
	require.NoError(t, err)
	require.True(t, info.Enabled)
	require.Error(t, m.Uninstall(ctx, manifest.ID, false))
	info, err = m.Get(manifest.ID)
	require.NoError(t, err)
	require.True(t, info.Enabled)
}
func TestExplicitDeactivateSuccessRetainsSettingsUntilUninstall(t *testing.T) {
	usePluginProcesses(t, pluginModeNormal)
	m := newTestManager(t)
	ctx := context.Background()
	m.Start(ctx)
	manifest := pluginManifest("official.deactivate")
	manifest.Permissions = append(manifest.Permissions, "lifecycle.deactivate")
	_, err := m.Install(ctx, buildTestPackage(t, manifest, nil), InstallOptions{Enable: true})
	require.NoError(t, err)
	info, err := m.Disable(ctx, manifest.ID)
	require.NoError(t, err)
	require.False(t, info.Enabled)
	require.DirExists(t, m.DataDir(manifest.ID))
	_, err = m.Enable(ctx, manifest.ID, false)
	require.NoError(t, err)
	require.NoError(t, m.Uninstall(ctx, manifest.ID, false))
}

func TestExplicitInstallFailsIfActivationNotConfirmed(t *testing.T) {
	usePluginProcesses(t, "activate-denied")
	m := newTestManager(t)
	ctx := context.Background()
	m.Start(ctx)
	manifest := pluginManifest("official.activation")
	manifest.Permissions = append(manifest.Permissions, "lifecycle.deactivate")
	_, err := m.Install(ctx, buildTestPackage(t, manifest, nil), InstallOptions{Enable: true})
	require.ErrorContains(t, err, "did not confirm activation")
	info, err := m.Get(manifest.ID)
	require.NoError(t, err)
	require.NotEmpty(t, info.LastError)
	_, err = m.Enable(ctx, manifest.ID, false)
	require.ErrorContains(t, err, "did not confirm activation")
}
