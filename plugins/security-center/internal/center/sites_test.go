package security_center

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func siteService(t *testing.T) *Service {
	s := testService(t)
	root := t.TempDir()
	s.SiteResolver = func(name string) (string, error) { return filepath.Join(root, name), nil }
	s.SiteLister = func() ([]string, error) { return []string{"a.conf", "b.conf"}, nil }
	for _, name := range []string{"a.conf", "b.conf"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("server { listen 80; server_name "+name+"; location / { return 200; } }\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		dump := fmt.Sprintf("# configuration file /etc/nginx/nginx.conf:\nevents {}\nhttp { include %s/*.conf; }\n", root)
		for _, name := range []string{"a.conf", "b.conf"} {
			path, _ := s.sitePath(name)
			body, _ := os.ReadFile(path)
			dump += fmt.Sprintf("# configuration file %s:\n%s\n", path, body)
			_, _, snippet := s.sitePaths(name)
			if strings.Contains(string(body), snippet) {
				content, err := os.ReadFile(snippet)
				if err != nil {
					return nil, err
				}
				dump += fmt.Sprintf("# configuration file %s:\n%s\n", snippet, content)
			}
		}
		return []byte(dump), nil
	}
	return s
}
func TestTwoSitesGlobalPropagationAndOverrides(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	p := inheritedPolicy()
	level := 2
	p.ParanoiaLevel = &level
	p.ExcludedRuleIDs = []int{941100}
	if _, err := s.ApplySite(ctx, "a.conf", p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySite(ctx, "b.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	global := validConfig()
	global.ParanoiaLevel = 3
	global.CrowdSecEnabled = true
	if err := s.ApplyWAF(ctx, global); err != nil {
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
	if a.Effective.ModSecurity.ParanoiaLevel != 2 || b.Effective.ModSecurity.ParanoiaLevel != 3 || !b.Effective.CrowdSec || len(a.Effective.ModSecurity.ExcludedRuleIDs) != 2 {
		t.Fatal(a, b)
	}
	_, aRules, _ := s.sitePaths("a.conf")
	_, bRules, _ := s.sitePaths("b.conf")
	ab, _ := os.ReadFile(aRules)
	bb, _ := os.ReadFile(bRules)
	if !strings.Contains(string(ab), "paranoia_level=2") || !strings.Contains(string(bb), "paranoia_level=3") {
		t.Fatal("effective policies not regenerated")
	}
}
func TestSingleSiteChangeDoesNotChangeOtherSite(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	for _, name := range []string{"a.conf", "b.conf"} {
		if _, err := s.ApplySite(ctx, name, inheritedPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	_, bRules, bSnippet := s.sitePaths("b.conf")
	before, _ := os.ReadFile(bRules)
	beforeSnippet, _ := os.ReadFile(bSnippet)
	p := inheritedPolicy()
	p.ModSecurity = "Off"
	p.CrowdSec = "off"
	if _, err := s.ApplySite(ctx, "a.conf", p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(bRules)
	afterSnippet, _ := os.ReadFile(bSnippet)
	if string(before) != string(after) || string(beforeSnippet) != string(afterSnippet) {
		t.Fatal("unrelated site changed")
	}
}
func TestGlobalValidationFailureRollsBackEveryFile(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	if err := s.ApplyWAF(ctx, validConfig()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.conf", "b.conf"} {
		if _, err := s.ApplySite(ctx, name, inheritedPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	snapshots := map[string]string{}
	snapshots[s.Config.ModSecurityPath] = ""
	for _, name := range []string{"a.conf", "b.conf"} {
		meta, rules, snippet := s.sitePaths(name)
		site, _ := s.sitePath(name)
		for _, path := range []string{meta, rules, snippet, site} {
			snapshots[path] = ""
		}
	}
	for path := range snapshots {
		b, _ := os.ReadFile(path)
		snapshots[path] = string(b)
	}
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-t" {
			return nil, errors.New("reject")
		}
		return []byte("# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"), nil
	}
	global := validConfig()
	global.Mode = "On"
	if s.ApplyWAF(ctx, global) == nil {
		t.Fatal("failure accepted")
	}
	for path, before := range snapshots {
		after, _ := os.ReadFile(path)
		if string(after) != before {
			t.Fatal("not rolled back", path)
		}
	}
}
func TestSiteConflictsAndTraversalRejected(t *testing.T) {
	s := siteService(t)
	if _, err := s.ApplySite(context.Background(), "../a.conf", inheritedPolicy()); err == nil {
		t.Fatal("traversal allowed")
	}
	path, _ := s.sitePath("a.conf")
	os.WriteFile(path, []byte("server { server_name a; location / { access_by_lua_block { return } } }"), 0644)
	if _, err := s.ApplySite(context.Background(), "a.conf", inheritedPolicy()); err == nil {
		t.Fatal("existing Lua hook overwritten")
	}
	if s.checkTopology([]byte("# configuration file /etc/nginx/nginx.conf:\nhttp { modsecurity_rules_file /etc/global-crs.conf; }\n")) == nil {
		t.Fatal("parent CRS inheritance allowed")
	}
}
func TestGlobalDefaultsWithoutSitesDoNotClaimReload(t *testing.T) {
	s := siteService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("no managed site: do not reload")
		return nil, nil
	}
	if err := s.ApplyWAF(context.Background(), validConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestLocalExceptionsAndBlockPathsRejectInjection(t *testing.T) {
	for _, path := range []string{"/x\nSecRuleEngine Off", "/x\" phase:1", "/x?query=1", "/x'"} {
		p := inheritedPolicy()
		p.BlockedPaths = []string{path}
		if validateLocalRules(p) == nil {
			t.Fatal("unsafe path", path)
		}
	}
	p := inheritedPolicy()
	p.Exceptions = []RuleException{{RuleID: 942100, Path: "/search", Parameter: "q;ctl:ruleEngine=Off"}}
	if validateLocalRules(p) == nil {
		t.Fatal("unsafe parameter")
	}
	p.Exceptions = []RuleException{{RuleID: 942100, Path: "/search", Parameter: "query"}}
	p.BlockedPaths = []string{"/private"}
	if err := validateLocalRules(p); err != nil {
		t.Fatal(err)
	}
	rendered := renderLocalRules(p)
	if !strings.Contains(rendered, "ctl:ruleRemoveTargetById=942100;ARGS:query") || !strings.Contains(rendered, "id:2100000") {
		t.Fatal(rendered)
	}
}
