package security_center

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	s := New(Config{Enabled: true, CrowdSecEnabled: true, ModSecurityEnabled: true, CSCLIPath: "/usr/bin/cscli", NginxPath: "/usr/sbin/nginx", ModSecurityPath: filepath.Join(t.TempDir(), "modsecurity.conf"), BaseConfig: "/etc/modsecurity/modsecurity.conf", CRSSetup: "/etc/modsecurity/crs/crs-setup.conf", CRSRules: "/usr/share/modsecurity-crs/rules/*.conf"})
	s.InstanceID = "controller-test"
	return s
}
func validConfig() WAFConfig {
	return WAFConfig{Mode: "DetectionOnly", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, ExcludedRuleIDs: []int{942100}}
}
func TestRejectsInjectionBeforeExecution(t *testing.T) {
	s := testService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) { t.Fatal("must not execute"); return nil, nil }
	ctx := context.Background()
	for _, ip := range []string{"127.0.0.1;touch /tmp/pwn", "--help", "1.2.3.4/0", "fe80::1%eth0"} {
		if s.AddDecision(ctx, Decision{IP: ip, Duration: "1h", Reason: "test"}) == nil {
			t.Errorf("accepted %q", ip)
		}
	}
	for _, name := range []string{"../../escape", "--help", "crowdsecurity/test;id", "crowdsecurity/x\nfoo"} {
		if s.Scenario(ctx, name, "install") == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if s.DeleteDecision(ctx, "1;id") == nil {
		t.Fatal("accepted invalid id")
	}
	c := validConfig()
	c.Mode = "On\nInclude /etc/passwd"
	if s.ApplyWAF(ctx, c) == nil {
		t.Fatal("accepted invalid mode")
	}
}
func TestDecisionUsesArgumentsNotShell(t *testing.T) {
	s := testService(t)
	var got []string
	s.Run = func(_ context.Context, path string, args ...string) ([]byte, error) {
		if path != "/usr/bin/cscli" {
			t.Fatal(path)
		}
		got = args
		return nil, nil
	}
	err := s.AddDecision(context.Background(), Decision{IP: "127.0.0.1", Duration: "1h", Reason: "test $(id)"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"decisions", "add", "--ip", "127.0.0.1", "--duration", "1h", "--reason", "test $(id)", "--type", "ban"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}
func TestDisabledAndScenarioReloadRequired(t *testing.T) {
	s := testService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) { t.Fatal("must not execute"); return nil, nil }
	if s.Scenario(context.Background(), "crowdsecurity/http-probing", "install") == nil {
		t.Fatal("missing reload accepted")
	}
	s.Config.Enabled = false
	if !errors.Is(s.AddDecision(context.Background(), Decision{}), ErrDisabled) {
		t.Fatal("disabled mutation accepted")
	}
}
func TestConfigValidation(t *testing.T) {
	for _, ids := range [][]int{{1}, {1000000}, {942100, 942100}} {
		c := validConfig()
		c.ExcludedRuleIDs = ids
		if c.Validate() == nil {
			t.Fatal("accepted IDs", ids)
		}
	}
	c := validConfig()
	c.ParanoiaLevel = 5
	if c.Validate() == nil {
		t.Fatal("accepted paranoia")
	}
}

func TestApplyRoundTrip(t *testing.T) {
	s := testService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("modsecurity on;\nmodsecurity_rules_file " + s.Config.ModSecurityPath + ";\n"), nil
	}
	c := validConfig()
	if err := s.ApplyWAF(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadWAF()
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatal(got, err)
	}
	b, _ := os.ReadFile(s.Config.ModSecurityPath)
	if !strings.Contains(string(b), "SecRuleRemoveById 942100") {
		t.Fatal("exclusion missing")
	}
}
func TestSymlinkAndUnmanagedFileRejected(t *testing.T) {
	s := testService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) { t.Fatal("must not execute"); return nil, nil }
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("original"), 0600)
	if err := os.Symlink(outside, s.Config.ModSecurityPath); err != nil {
		t.Fatal(err)
	}
	if s.ApplyWAF(context.Background(), validConfig()) == nil {
		t.Fatal("followed symlink")
	}
	os.Remove(s.Config.ModSecurityPath)
	os.WriteFile(s.Config.ModSecurityPath, []byte("unmanaged"), 0600)
	if s.ApplyWAF(context.Background(), validConfig()) == nil {
		t.Fatal("replaced unmanaged file")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "original" {
		t.Fatal("modified outside file")
	}
}

func TestScenarioMutationReloadAndFailureReporting(t *testing.T) {
	s := testService(t)
	s.Config.CrowdSecReloadPath = "/usr/local/bin/reload-crowdsec"
	var paths []string
	s.Run = func(_ context.Context, path string, args ...string) ([]byte, error) {
		paths = append(paths, path)
		if len(paths) == 1 && !reflect.DeepEqual(args, []string{"scenarios", "install", "crowdsecurity/http-probing"}) {
			t.Fatal(args)
		}
		if path == s.Config.CrowdSecReloadPath {
			return nil, errors.New("restart error")
		}
		return nil, nil
	}
	err := s.Scenario(context.Background(), "crowdsecurity/http-probing", "install")
	if err == nil || !strings.Contains(err.Error(), "files changed") || len(paths) != 2 {
		t.Fatal("partial mutation was not reported", paths, err)
	}
}

func TestDecisionListHasExplicitLimitAndExcludesSimulation(t *testing.T) {
	s := testService(t)
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		want := []string{"decisions", "list", "-o", "json", "--limit", "100", "--no-simu"}
		if !reflect.DeepEqual(args, want) {
			t.Fatal(args)
		}
		return []byte(`[]`), nil
	}
	if _, err := s.List(context.Background(), "decisions"); err != nil {
		t.Fatal(err)
	}
}

func TestScenarioCatalogIncludesAvailableEntries(t *testing.T) {
	s := testService(t)
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"scenarios", "list", "-o", "json", "-a"}) {
			t.Fatal(args)
		}
		return []byte(`{"scenarios":[]}`), nil
	}
	if _, err := s.List(context.Background(), "scenarios"); err != nil {
		t.Fatal(err)
	}
}

func TestCentralScenarioReceiptAvoidsSecondRestart(t *testing.T) {
	s := testService(t)
	s.Config.CrowdSecReloadPath = "/reload"
	calls := 0
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		calls++
		return []byte(`{"engine_reloaded":true}`), nil
	}
	if err := s.Scenario(context.Background(), "crowdsecurity/test", "install"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("central engine restarted twice")
	}
}
