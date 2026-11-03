package security_center

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func customTemplate() PolicyTemplate {
	p := inheritedPolicy()
	p.ModSecurity = "On"
	return PolicyTemplate{ID: "my-gitlab", Name: "My GitLab", Description: "Validated local settings", Policy: p}
}
func TestTemplatesRoundTripWithoutRuntimeMutation(t *testing.T) {
	s := testService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("template operation executed runtime command")
		return nil, nil
	}
	items, err := s.Templates()
	if err != nil || len(items) != 3 {
		t.Fatalf("builtins: %v %v", items, err)
	}
	p := customTemplate()
	p.Policy.ModSecurity = "Off"
	p.Policy.CrowdSec = "off"
	p.Policy.ExcludedRuleIDs = []int{941100}
	p.Policy.Exceptions = []RuleException{{RuleID: 942100, Path: "/search", Parameter: "q"}}
	if err = s.SaveTemplate(p); err != nil {
		t.Fatal(err)
	}
	items, err = s.Templates()
	if err != nil || !reflect.DeepEqual(items[3], p) {
		t.Fatalf("roundtrip: %+v %v", items, err)
	}
	if _, err = os.Stat(s.Config.ModSecurityPath); !os.IsNotExist(err) {
		t.Fatal("template save changed global runtime policy")
	}
	p.Name = "Changed"
	if err = s.SaveTemplate(p); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTemplate(p.ID); err != nil {
		t.Fatal(err)
	}
	items, err = s.Templates()
	if err != nil || len(items) != 3 {
		t.Fatal(items, err)
	}
}
func TestTemplatesRejectInvalidAndImmutableInputs(t *testing.T) {
	s := testService(t)
	for _, id := range []string{"../escape", "a/b", "A", "generic", "exchange-onprem", "gitlab", "x\n"} {
		p := customTemplate()
		p.ID = id
		if !errors.Is(s.SaveTemplate(p), ErrInvalid) {
			t.Fatalf("accepted %q", id)
		}
		if !errors.Is(s.DeleteTemplate(id), ErrInvalid) {
			t.Fatalf("deleted %q", id)
		}
	}
	for _, change := range []func(*PolicyTemplate){func(p *PolicyTemplate) { p.Builtin = true }, func(p *PolicyTemplate) { p.Name = "\n" }, func(p *PolicyTemplate) { p.Description = strings.Repeat("x", 1001) }, func(p *PolicyTemplate) { p.Policy.ModSecurity = "invalid" }, func(p *PolicyTemplate) { p.Policy.BlockedPaths = []string{"/x\nSecRuleEngine Off"} }} {
		p := customTemplate()
		change(&p)
		if !errors.Is(s.SaveTemplate(p), ErrInvalid) {
			t.Fatal("invalid template accepted")
		}
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.templatePath()); err != nil {
		t.Fatal(err)
	}
	if s.SaveTemplate(customTemplate()) == nil {
		t.Fatal("symlink accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "secret" {
		t.Fatal("symlink target changed")
	}
}
func TestTemplateEditDeleteDoesNotChangeAppliedSite(t *testing.T) {
	s := siteService(t)
	p := customTemplate()
	if err := s.SaveTemplate(p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySite(context.Background(), "a.conf", p.Policy); err != nil {
		t.Fatal(err)
	}
	state, rules, snippet := s.sitePaths("a.conf")
	paths := []string{state, rules, snippet}
	before := map[string]string{}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = string(b)
	}
	p.Policy.ModSecurity = "Off"
	if err := s.SaveTemplate(p); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTemplate(p.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != before[path] {
			t.Fatal("template changed applied policy", path, err)
		}
	}
}
func TestTemplateStorageBound(t *testing.T) {
	s := testService(t)
	p := customTemplate()
	items := make([]PolicyTemplate, 100)
	for i := range items {
		items[i] = p
		items[i].ID = "custom-" + strings.Repeat("a", i%50) + string(rune('a'+i/50))
	}
	// Oversized storage and duplicate/corrupt stored records must never be accepted.
	p.Description = strings.Repeat("x", 1000)
	for i := range items {
		items[i].Description = p.Description
	}
	if !errors.Is(s.writeTemplates(items), ErrInvalid) {
		t.Fatal("oversized catalogue accepted")
	}
	if err := os.WriteFile(s.templatePath(), []byte(`[{"id":"../x"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Templates(); err == nil {
		t.Fatal("corrupt catalogue accepted")
	}
}

func TestConcurrentTemplateSavesPreserveAllEntries(t *testing.T) {
	s := testService(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := customTemplate()
			p.ID = fmt.Sprintf("custom-%d", i)
			errs <- s.SaveTemplate(p)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.Templates()
	if err != nil || len(items) != 23 {
		t.Fatalf("lost concurrent save: %d %v", len(items), err)
	}
}
