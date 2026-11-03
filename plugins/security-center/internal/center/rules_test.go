package security_center

import (
	"context"

	"os"
	"path/filepath"
	"testing"
)

func TestRuleCatalogIgnoresCommentsAndJoinsActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "REQUEST-941.conf")
	input := "# SecRule ARGS x \"id:999999,msg:'disabled'\"\nSecRule ARGS x \\\n  \"id:941100,\\\n  msg:'XSS Attack Detected'\"\nSecAction \"id:900110,pass,nolog\"\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Enabled: true, ModSecurityEnabled: true, CRSRules: filepath.Join(dir, "*.conf")})
	got, err := s.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 || got.Items[1].ID != 941100 || got.Items[1].Message != "XSS Attack Detected" || got.Items[1].File != "REQUEST-941.conf" {
		t.Fatalf("unexpected catalog: %+v", got)
	}
}
func TestRuleCatalogRejectsSymlinkAndDisabled(t *testing.T) {
	dir := t.TempDir()
	os.Symlink("/etc/passwd", filepath.Join(dir, "link.conf"))
	s := New(Config{Enabled: true, ModSecurityEnabled: true, CRSRules: filepath.Join(dir, "*.conf")})
	if _, err := s.Rules(context.Background()); err == nil {
		t.Fatal("symlink accepted")
	}
	s.Config.Enabled = false
	if _, err := s.Rules(context.Background()); err != ErrDisabled {
		t.Fatalf("disabled: %v", err)
	}
}
