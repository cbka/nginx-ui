package security_center

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

func validAppSecMode(mode string) bool {
	return mode == "" || mode == "off" || mode == "detection" || mode == "block"
}

// Inventory is read-only. Installed files and a listening socket do not prove
// that a particular request was inspected; keep those facts separate.
func (s *Service) AppSecInventory(ctx context.Context) (json.RawMessage, error) {
	if err := s.crowdsec(); err != nil {
		return nil, err
	}
	b, err := s.Run(ctx, s.Config.CSCLIPath, "appsec", "status")
	if err != nil {
		return nil, err
	}
	var wire struct {
		Enabled *bool             `json:"enabled"`
		Ready   *bool             `json:"ready"`
		Rules   []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(b, &wire) != nil || wire.Enabled == nil || wire.Ready == nil || wire.Rules == nil {
		return nil, errors.New("CrowdSec returned invalid AppSec inventory")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(b, &result) != nil {
		return nil, ErrInvalid
	}
	counts := map[string]int{"off": 0, "detection": 0, "block": 0}
	s.mu.Lock()
	states, stateErr := s.states()
	if stateErr == nil && len(states) > 0 {
		global, e := s.readWAF()
		stateErr = e
		for _, state := range states {
			g := global
			if state.Replica && state.GlobalSnapshot != nil {
				g = *state.GlobalSnapshot
			}
			effective, e := effectivePolicy(g, state.Policy)
			if e != nil {
				stateErr = e
				break
			}
			counts[effective.AppSec]++
		}
	}
	s.mu.Unlock()
	if stateErr != nil {
		return nil, stateErr
	}
	result["site_counts"], _ = json.Marshal(counts)
	// This checks a loaded generated directive, not end-to-end traffic coverage.
	verified := false
	if s.Config.AppSecEnabled {
		verified = s.AppSecRuntimeReady(ctx)
	}
	result["runtime_integration_verified"], _ = json.Marshal(verified)
	result["runtime_configured"], _ = json.Marshal(s.Config.AppSecEnabled)
	return json.Marshal(result)
}

// AppSecRuntimeReady proves generated AppSec directives and its Lua transport
// are present, but does not infer successful request inspection from that.
func (s *Service) AppSecRuntimeReady(ctx context.Context) bool {
	if !s.Config.Enabled || !s.Config.CrowdSecEnabled || !s.Config.AppSecEnabled {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil || s.checkTopology(dump) != nil {
		return false
	}
	if !strings.Contains(string(dump), "set $nginx_ui_appsec_mode ") || !strings.Contains(string(dump), "set $crowdsec_disable_appsec 1;") {
		return false
	}
	for _, path := range []string{"/usr/local/lua/nginx-ui/nginx_ui_appsec.lua", "/etc/crowdsec/bouncers/nginx-ui-appsec.json"} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return false
		}
	}
	hook, err := os.ReadFile(accessHook)
	return err == nil && strings.Contains(string(hook), "nginx_ui_appsec")
}
