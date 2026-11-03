package plugin

import (
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"slices"
)

// InitializeResult returns what a running plugin answered during its
// handshake. The http capability uses it to find the Windows loopback port a
// plugin reports in place of a Unix socket.
func (m *Manager) InitializeResult(id string) (protocol.InitializeResult, bool) {
	item, ok := m.lookup(id)
	if !ok {
		return protocol.InitializeResult{}, false
	}

	m.mu.RLock()
	supervisor := item.supervisor
	m.mu.RUnlock()
	if supervisor == nil {
		return protocol.InitializeResult{}, false
	}
	return supervisor.InitializeResult()
}

// HTTPSecret returns the secret the running process of a plugin expects on
// every request to its http listener, and false when it has none.
func (m *Manager) HTTPSecret(id string) (string, bool) {
	item, ok := m.lookup(id)
	if !ok {
		return "", false
	}

	m.mu.RLock()
	supervisor := item.supervisor
	m.mu.RUnlock()
	if supervisor == nil {
		return "", false
	}
	return supervisor.HTTPSecret()
}

// PrivilegedHTTP reports the signed manifest's local administrative requirement.
func (m *Manager) PrivilegedHTTP(id string) bool {
	item, ok := m.lookup(id)
	if !ok {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Contains(item.manifest.Permissions, "http.privileged")
}
