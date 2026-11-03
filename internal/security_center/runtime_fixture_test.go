package security_center

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xJacky/Nginx-UI/settings"
)

// TestGenerateRuntimeFixtures is an opt-in bridge to packaging/security's real
// Nginx smoke tests. Both containers mount this directory at /security-fixtures.
// No production configuration or credentials are accessed.
func TestGenerateRuntimeFixtures(t *testing.T) {
	if os.Getenv("NGINX_UI_GENERATE_SECURITY_FIXTURES") != "true" {
		t.Skip("opt-in real-runtime fixture generation")
	}
	root := "/security-fixtures"
	for _, dir := range []string{"policies", "sites"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0750); err != nil {
			t.Fatal(err)
		}
	}
	s := New(settings.SecurityCenter{Enabled: true, CrowdSecEnabled: true, ModSecurityEnabled: true, CSCLIPath: "/usr/bin/cscli", NginxPath: "/usr/sbin/nginx", ModSecurityPath: root + "/policies/modsecurity.conf", BaseConfig: "/etc/modsecurity/modsecurity.conf", CRSSetup: "/etc/modsecurity/crs/crs-setup.conf", CRSRules: "/usr/share/modsecurity-crs/rules/*.conf"})
	s.InstanceID = "runtime-fixture-controller"
	s.SiteResolver = func(name string) (string, error) { return filepath.Join(root, "sites", name), nil }
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("# configuration file /etc/nginx/nginx.conf:\nevents {}\nhttp {}\n"), nil
	}
	configs := map[string]string{"a.conf": "server { listen 8081; server_name a.test; location / { proxy_pass http://127.0.0.1:8080; } }\n", "b.conf": "server { listen 8082; server_name b.test; location / { proxy_pass http://127.0.0.1:8080; } }\n"}
	for name, content := range configs {
		if err := os.WriteFile(filepath.Join(root, "sites", name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	global := WAFConfig{Mode: "On", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, CrowdSecEnabled: true, ExcludedRuleIDs: []int{}}
	if err := s.ApplyWAF(context.Background(), global); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySite(context.Background(), "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	policy := inheritedPolicy()
	policy.ModSecurity = "On"
	policy.CrowdSec = "off"
	policy.ExcludedRuleIDs = []int{999998}
	policy.Exceptions = []RuleException{{RuleID: 999997, Path: "/search", Parameter: "query"}}
	policy.BlockedPaths = []string{"/private"}
	if _, err := s.ApplySite(context.Background(), "b.conf", policy); err != nil {
		t.Fatal(err)
	}
}
