package security_center

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAllowlistValidationAndCanonicalUnion(t *testing.T) {
	got, err := mergeIPAllowlist([]string{"192.0.2.4", "2001:db8::1", "192.0.2.99/24"}, []string{"192.0.2.0/24"})
	want := []string{"192.0.2.0/24", "192.0.2.4/32", "2001:db8::1/128"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, value := range []string{"", "example.org", "10.0.0.1;deny", "0.0.0.0/33", "::/129", "fe80::1%eth0", "10.0.0.1\n", "::ffff:192.0.2.0/120", " 10.0.0.1"} {
		t.Run(value, func(t *testing.T) {
			if _, err := mergeIPAllowlist([]string{value}); err == nil {
				t.Fatal("accepted invalid address")
			}
		})
	}
}

func TestAllowlistSiteIsolationPersistenceAndRuleOrdering(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	global := validConfig()
	global.ModSecurityAllowlist = []string{"192.0.2.1"}
	global.CrowdSecAllowlist = []string{"2001:db8::/32"}
	if err := s.ApplyWAF(ctx, global); err != nil {
		t.Fatal(err)
	}
	p := inheritedPolicy()
	p.ModSecurityAllowlist = []string{"198.51.100.0/24"}
	p.CrowdSecAllowlist = []string{"203.0.113.9"}
	p.BlockedPaths = []string{"/private"}
	if _, err := s.ApplySite(ctx, "a.conf", p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySite(ctx, "b.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.GetSite("b.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Effective.ModSecurity.ModSecurityAllowlist) != 2 || len(b.Effective.ModSecurity.ModSecurityAllowlist) != 1 || len(a.Policy.CrowdSecAllowlist) != 1 {
		t.Fatal("scope or persistence failed")
	}
	_, rules, snippet := s.sitePaths("a.conf")
	data, _ := os.ReadFile(rules)
	text := string(data)
	allow := strings.Index(text, "SecRule REMOTE_ADDR")
	if allow < 0 || allow > strings.Index(text, "id:2100000") || allow > strings.Index(text, "Include \""+s.Config.CRSRules) || !strings.Contains(text, "ctl:ruleEngine=Off") {
		t.Fatal("allowlist must precede local and CRS rules")
	}
	data, _ = os.ReadFile(snippet)
	if !strings.Contains(string(data), `set $nginx_ui_crowdsec_allowlist "2001:db8::/32,203.0.113.9/32";`) {
		t.Fatal(string(data))
	}
	if strings.Contains(strings.SplitN(text, "\n", 2)[1], "203.0.113.9") {
		t.Fatal("CrowdSec allowlist leaked into WAF enforcement rule")
	}
}

func TestAllowlistReplicationCarriesSourceDefaultsAndLocalRanges(t *testing.T) {
	source, peer := siteService(t), siteService(t)
	source.InstanceID, peer.InstanceID = "source", "peer"
	ctx := context.Background()
	global := validConfig()
	global.ModSecurityAllowlist = []string{"192.0.2.0/24"}
	global.CrowdSecAllowlist = []string{"2001:db8::/32"}
	if err := source.ApplyWAF(ctx, global); err != nil {
		t.Fatal(err)
	}
	policy := inheritedPolicy()
	policy.CrowdSecAllowlist = []string{"198.51.100.8"}
	if _, err := source.ApplySite(ctx, "a.conf", policy); err != nil {
		t.Fatal(err)
	}
	payload, err := source.ExportSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.ApplyReplica(ctx, payload, "source"); err != nil {
		t.Fatal(err)
	}
	view, err := peer.GetSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Effective.ModSecurity.ModSecurityAllowlist, []string{"192.0.2.0/24"}) || len(view.Effective.ModSecurity.CrowdSecAllowlist) != 2 {
		t.Fatal("source allowlists not replicated", view.Effective)
	}
	// Invalid input must leave previously committed generated files unchanged.
	_, rules, _ := source.sitePaths("a.conf")
	before, _ := os.ReadFile(rules)
	policy.ModSecurityAllowlist = []string{"192.0.2.1\";"}
	if _, err := source.ApplySite(ctx, "a.conf", policy); err == nil {
		t.Fatal("invalid range accepted")
	}
	after, _ := os.ReadFile(rules)
	if string(before) != string(after) {
		t.Fatal("invalid policy modified active rules")
	}
}

func TestModSecurityIPv6HostRendering(t *testing.T) {
	s := siteService(t)
	c := validConfig()
	c.ModSecurityAllowlist = []string{"::1", "2001:db8::/64", "192.0.2.3"}
	b, err := s.render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"@ipMatch 192.0.2.3/32,2001:db8::/64,::1"`) {
		t.Fatal(string(b))
	}
}

func TestModSecurityZeroMaskRendering(t *testing.T) {
	if got := modSecurityIPMatch([]string{"0.0.0.0/0", "::/0"}); got != "0.0.0.0/1,128.0.0.0/1,::/1,8000::/1" {
		t.Fatal(got)
	}
}
