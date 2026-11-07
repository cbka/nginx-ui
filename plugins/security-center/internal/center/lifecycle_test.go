package security_center

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetachOnlyOwnedInclude(t *testing.T) {
	content := "server { listen 80; include /owned/security.conf; include /other.conf; location / { return 200; } }"
	out, err := detach(content, "/owned/security.conf")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "/owned/security.conf") || !strings.Contains(out, "/other.conf") || !strings.Contains(out, "return 200") {
		t.Fatal("detach changed unrelated directives")
	}
}
func TestTransactionUsesOriginalSiteSnapshot(t *testing.T) {
	s := testService(t)
	path := filepath.Join(t.TempDir(), "site.conf")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	s.remember(path, []byte("original"), false)
	if err := os.WriteFile(path, []byte("concurrent edit"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Transaction = func(_ context.Context, c []Change) error {
		if c[0].ExpectedSHA256 != digest([]byte("original")) {
			t.Fatal("lost original CAS snapshot")
		}
		return errors.New("conflict")
	}
	if s.applyFiles(context.Background(), []fileChange{{path, []byte("candidate")}}) == nil {
		t.Fatal("expected conflict")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "concurrent edit" {
		t.Fatal("plugin wrote around host transaction")
	}
}
func TestDeactivateRestoreAndFailedReload(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	if _, err := s.ApplySite(ctx, "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	path, _ := s.sitePath("a.conf")
	before, _ := os.ReadFile(path)
	meta, _, snippet := s.sitePaths("a.conf")
	saved, _ := os.ReadFile(meta)
	s.Transaction = func(context.Context, []Change) error { return errors.New("reload failed") }
	if s.Deactivate(ctx) == nil {
		t.Fatal("failed reload must prevent deactivation")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("failed host transaction mutated local files")
	}
	s.Transaction = nil
	if err := s.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	if strings.Contains(string(after), snippet) {
		t.Fatal("enforcement include remains")
	}
	retained, _ := os.ReadFile(meta)
	if string(retained) != string(saved) {
		t.Fatal("desired policy was erased")
	}
	if err := s.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	if !strings.Contains(string(after), snippet) {
		t.Fatal("saved protection not restored")
	}
}
func TestMigrateLegacyPreservesOwnershipAndTemplates(t *testing.T) {
	old := siteService(t)
	ctx := context.Background()
	if err := old.ApplyWAF(ctx, validConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := old.ApplySite(ctx, "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveTemplate(PolicyTemplate{ID: "custom", Name: "Custom", Policy: inheritedPolicy()}); err != nil {
		t.Fatal(err)
	}
	s := New(old.Config)
	s.Config.ModSecurityPath = filepath.Join(t.TempDir(), "modsecurity.conf")
	s.SiteResolver = old.SiteResolver
	s.SiteLister = old.SiteLister
	s.InstanceID = old.InstanceID
	s.Run = old.Run
	if err := s.Migrate(ctx, filepath.Dir(old.Config.ModSecurityPath)); err != nil {
		t.Fatal(err)
	}
	path, _ := s.sitePath("a.conf")
	b, _ := os.ReadFile(path)
	_, _, legacy := old.sitePaths("a.conf")
	_, _, current := s.sitePaths("a.conf")
	if strings.Contains(string(b), legacy) || !strings.Contains(string(b), current) {
		t.Fatal("migration left duplicate or missing includes")
	}
	a, err := s.GetSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	templates, err := s.readTemplates()
	if err != nil || len(templates) != 1 || templates[0].ID != "custom" {
		t.Fatal("custom template was not migrated", err)
	}
	original, _ := old.GetSite("a.conf")
	if a.Owner != original.Owner || a.Revision != original.Revision {
		t.Fatal("migration changed ownership")
	}
}
func TestDeactivateRejectsUnownedGlobalEnforcement(t *testing.T) {
	s := siteService(t)
	if _, err := s.ApplySite(context.Background(), "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "bulk" && args[1] == "cancel" {
			return []byte("null"), nil
		}
		return []byte("# configuration file /etc/nginx/nginx.conf:\nhttp { access_by_lua_file /unowned.lua; }\n"), nil
	}
	if s.Deactivate(context.Background()) == nil {
		t.Fatal("must not claim security is off with unowned enforcement")
	}
}

func TestDeactivateWithoutOwnedSitesLeavesUnownedLuaUntouched(t *testing.T) {
	s := siteService(t)
	path, err := s.sitePath("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("server { listen 80; access_by_lua_file /existing-auth.lua; }\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "bulk" && args[1] == "cancel" {
			return []byte("null"), nil
		}
		t.Fatal("no owned sites: must not inspect or reload unrelated Nginx configuration")
		return nil, nil
	}
	s.Transaction = func(context.Context, []Change) error {
		t.Fatal("no owned sites: must not submit a configuration transaction")
		return nil
	}
	if err := s.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(content) {
		t.Fatal("deactivation changed the existing Lua authentication configuration", err)
	}
}
