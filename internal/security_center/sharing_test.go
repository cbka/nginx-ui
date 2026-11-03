package security_center

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sharingBase = "api:\n  server:\n    online_client:\n      sharing: false\n      credentials_path: /secret/credentials.yaml\nother: keep\n"

func sharingService(t *testing.T) *Service {
	s := testService(t)
	s.Config.SharingConfigPath = filepath.Join(t.TempDir(), "config.yaml")
	s.Config.SharingValidatePath = "/validate"
	s.Config.CrowdSecReloadPath = "/reload"
	if err := os.WriteFile(s.Config.SharingConfigPath, []byte(sharingBase), 0600); err != nil {
		t.Fatal(err)
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	return s
}
func TestSharingUnknownNotFalseAndMissingIntegration(t *testing.T) {
	s := testService(t)
	v := s.Sharing()
	if v.Enabled != nil || v.Configured || v.Editable || v.RuntimeVerified {
		t.Fatal(v)
	}
	s = sharingService(t)
	if err := os.WriteFile(s.Config.SharingConfigPath, []byte("api: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v = s.Sharing()
	if v.Enabled != nil || !v.Configured || !v.Editable || v.RuntimeVerified {
		t.Fatal(v)
	}
	s.Config.SharingValidatePath = ""
	if s.Sharing().Editable || s.SetSharing(context.Background(), true) == nil {
		t.Fatal("missing validation allowed edit")
	}
}
func TestSharingHonorsLocalOverrideAndPreservesBase(t *testing.T) {
	s := sharingService(t)
	local := s.Config.SharingConfigPath + ".local"
	if err := os.WriteFile(local, []byte("api:\n  server:\n    online_client:\n      sharing: true\ncustom: unchanged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v := s.Sharing()
	if v.Enabled == nil || !*v.Enabled {
		t.Fatal(v)
	}
	var calls []string
	s.Run = func(_ context.Context, p string, args ...string) ([]byte, error) {
		if len(args) != 0 {
			t.Fatal("unexpected hook args")
		}
		calls = append(calls, p)
		return nil, nil
	}
	if err := s.SetSharing(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(s.Config.SharingConfigPath)
	if string(b) != sharingBase {
		t.Fatal("base changed despite localoverride")
	}
	b, _ = os.ReadFile(local)
	if !strings.Contains(string(b), "custom: unchanged") {
		t.Fatal("unrelated setting lost")
	}
	v = s.Sharing()
	if v.Enabled == nil || *v.Enabled || v.RuntimeVerified || len(calls) != 2 {
		t.Fatal(v, calls)
	}
}
func TestSharingRollbackValidationAndReloadFailure(t *testing.T) {
	for _, stage := range []string{"/validate", "/reload"} {
		t.Run(stage, func(t *testing.T) {
			s := sharingService(t)
			failed := false
			calls := 0
			s.Run = func(_ context.Context, p string, _ ...string) ([]byte, error) {
				calls++
				if p == stage && !failed {
					failed = true
					return nil, errors.New("failure with secret")
				}
				return nil, nil
			}
			err := s.SetSharing(context.Background(), true)
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(s.Config.SharingConfigPath)
			if string(b) != sharingBase {
				t.Fatal("rollback failed")
			}
			if stage == "/reload" && calls != 3 {
				t.Fatal("missing recoveryreload", calls)
			}
		})
	}
}
func TestSharingRejectsAmbiguousYAMLAndSymlinks(t *testing.T) {
	for _, input := range []string{"api: {}\napi: {}\n", "api: &a {}\nother: *a\n", "api: {}\n---\napi: {}\n", "api:\n server:\n  online_client:\n   sharing: maybe\n"} {
		s := sharingService(t)
		if err := os.WriteFile(s.Config.SharingConfigPath, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if s.Sharing().Enabled != nil || s.SetSharing(context.Background(), true) == nil {
			t.Fatal("ambiguous YAML accepted")
		}
	}
	s := sharingService(t)
	local := s.Config.SharingConfigPath + ".local"
	if err := os.Symlink(s.Config.SharingConfigPath, local); err != nil {
		t.Fatal(err)
	}
	if s.SetSharing(context.Background(), true) == nil {
		t.Fatal("symlink local accepted")
	}
}
func TestSharingBaseWritePreservesCredentialReference(t *testing.T) {
	s := sharingService(t)
	if err := s.SetSharing(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(s.Config.SharingConfigPath)
	if !strings.Contains(string(b), "credentials_path: /secret/credentials.yaml") || !strings.Contains(string(b), "other: keep") {
		t.Fatal("unrelated configuration changed")
	}
	v := s.Sharing()
	if v.Enabled == nil || !*v.Enabled || v.RuntimeVerified {
		t.Fatal(v)
	}
}
