package security_center

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAppSecModesAndLegacy(t *testing.T) {
	g := validConfig()
	p := inheritedPolicy()
	e, err := effectivePolicy(g, p)
	if err != nil || e.AppSec != "off" {
		t.Fatalf("legacy must be off: %v %v", e.AppSec, err)
	}
	for _, mode := range []string{"off", "detection", "block"} {
		g.AppSecMode = mode
		e, err = effectivePolicy(g, p)
		if err != nil || e.AppSec != mode {
			t.Fatalf("inherit %s: %v", mode, err)
		}
		p.AppSec = "off"
		e, err = effectivePolicy(g, p)
		if err != nil || e.AppSec != "off" {
			t.Fatal("explicit off failed")
		}
		p.AppSec = "inherit"
	}
	p.AppSec = "block; injected"
	if _, err = effectivePolicy(g, p); err == nil {
		t.Fatal("invalid site mode accepted")
	}
	g.AppSecMode = "unknown"
	if g.Validate() == nil {
		t.Fatal("invalid global mode accepted")
	}
}
func TestAppSecInventoryDisabledDoesNotExecute(t *testing.T) {
	s := testService(t)
	s.Config.Enabled = false
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("disabled executed")
		return nil, nil
	}
	if _, err := s.AppSecInventory(context.Background()); err != ErrDisabled {
		t.Fatalf("%v", err)
	}
}
func TestAppSecInventoryValidatesJSON(t *testing.T) {
	s := testService(t)
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) != 2 || args[0] != "appsec" || args[1] != "status" {
			t.Fatalf("%v", args)
		}
		return []byte(`{"enabled":true,"ready":true,"rules":[],"configs":[],"collections":[]}`), nil
	}
	b, err := s.AppSecInventory(context.Background())
	if err != nil || !json.Valid(b) {
		t.Fatal(err)
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte(`{"ready":"yes"}`), nil }
	if _, err = s.AppSecInventory(context.Background()); err == nil {
		t.Fatal("invalid schema accepted")
	}
}

func TestAppSecPolicyReplicationAndLifecycle(t *testing.T) {
	source, peer := siteService(t), siteService(t)
	source.Config.AppSecEnabled = true
	peer.Config.AppSecEnabled = true
	source.InstanceID = "source"
	peer.InstanceID = "peer"
	ctx := context.Background()
	g := validConfig()
	g.AppSecMode = "detection"
	if err := source.ApplyWAF(ctx, g); err != nil {
		t.Fatal(err)
	}
	p := inheritedPolicy()
	p.CrowdSec = "off"
	p.ModSecurity = "Off"
	p.AppSec = "block"
	if _, err := source.ApplySite(ctx, "a.conf", p); err != nil {
		t.Fatal(err)
	}
	payload, err := source.ExportSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = peer.ApplyReplica(ctx, payload, "source"); err != nil {
		t.Fatal(err)
	}
	response, err := peer.GetSite("a.conf")
	if err != nil || response.Effective.AppSec != "block" || response.Effective.CrowdSec {
		t.Fatal("independent mode replication failed", err)
	}
	_, _, snippet := peer.sitePaths("a.conf")
	b, err := os.ReadFile(snippet)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set $nginx_ui_appsec_mode block;", "set $crowdsec_disable_appsec 1;", "set $nginx_ui_crowdsec_enabled 0;"} {
		if !strings.Contains(string(b), want) {
			t.Fatal("missing directive", want)
		}
	}
	if err = peer.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	path, _ := peer.sitePath("a.conf")
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), snippet) {
		t.Fatal("plugin-off left AppSec attached")
	}
}

func TestAppSecRuleMutationRequiresVerifiedReceipt(t *testing.T) {
	s := testService(t)
	s.Config.AppSecEnabled = true
	name := "crowdsecurity/vpatch-CVE-2026-1234"
	called := 0
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		called++
		if len(args) != 3 || args[0] != "appsec-rules" || args[2] != name {
			t.Fatal(args)
		}
		return []byte(`{"applied":true,"loaded":true,"name":"crowdsecurity/vpatch-CVE-2026-1234"}`), nil
	}
	if err := s.ChangeAppSecRule(context.Background(), name, "activate"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"evil/vpatch-test", "crowdsecurity/generic-test", "crowdsecurity/vpatch-../../etc"} {
		if s.ChangeAppSecRule(context.Background(), bad, "install") == nil {
			t.Fatal(bad)
		}
	}
	if called != 1 {
		t.Fatal("invalid names executed")
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"applied":true,"loaded":false}`), nil
	}
	if s.ChangeAppSecRule(context.Background(), name, "install") == nil {
		t.Fatal("unverified activation accepted")
	}
}
