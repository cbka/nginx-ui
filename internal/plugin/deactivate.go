package plugin

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// deactivateEntry is deliberately separate from stopEntry: crashes, upgrades,
// process restarts and host shutdown must not silently detach configuration.
func (m *Manager) deactivateEntry(ctx context.Context, item *entry, reason string) (err error) {
	defer func() {
		if err != nil {
			m.recordError(item, err)
		}
	}()
	m.mu.RLock()
	required := slices.Contains(item.manifest.Permissions, "lifecycle.deactivate")
	enabled := item.row != nil && item.row.Enabled
	m.mu.RUnlock()
	if !required || !enabled {
		return nil
	}
	supervisor, err := m.ensureSupervisor(item)
	if err != nil {
		return err
	}
	if supervisor == nil {
		return fmt.Errorf("plugin %s cannot deactivate without a process", item.id)
	}
	caller, release, err := supervisor.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("plugin %s must be running to deactivate safely: %w", item.id, err)
	}
	defer release()
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result struct {
		Deactivated bool `json:"deactivated"`
	}
	if err := caller.Call(callCtx, "plugin.deactivate", map[string]string{"reason": reason}, &result); err != nil {
		return fmt.Errorf("plugin %s deactivation failed: %w", item.id, err)
	}
	if !result.Deactivated {
		return fmt.Errorf("plugin %s did not confirm complete deactivation", item.id)
	}
	return nil
}

// activateEntry makes an explicit enable/install wait for enforcement readiness,
// rather than treating a successful transport handshake as activation success.
func (m *Manager) activateEntry(ctx context.Context, item *entry) (err error) {
	defer func() {
		if err != nil {
			m.recordError(item, err)
		}
	}()
	m.mu.RLock()
	required := slices.Contains(item.manifest.Permissions, "lifecycle.deactivate")
	enabled := item.row != nil && item.row.Enabled
	offline := m.offline
	m.mu.RUnlock()
	if !required || !enabled || offline {
		return nil
	}
	supervisor, err := m.ensureSupervisor(item)
	if err != nil {
		return err
	}
	if supervisor == nil {
		return fmt.Errorf("plugin %s cannot activate without a process", item.id)
	}
	caller, release, err := supervisor.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	var result struct {
		Activated bool `json:"activated"`
	}
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err = caller.Call(callCtx, "plugin.activate", struct{}{}, &result); err != nil {
		return fmt.Errorf("plugin %s activation failed: %w", item.id, err)
	}
	if !result.Activated {
		return fmt.Errorf("plugin %s did not confirm activation", item.id)
	}
	return nil
}
