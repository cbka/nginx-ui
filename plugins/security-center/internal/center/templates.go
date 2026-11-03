package security_center

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type PolicyTemplate struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Builtin     bool       `json:"builtin"`
	Policy      SitePolicy `json:"policy"`
}

var templateID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func builtinTemplates() []PolicyTemplate {
	policy := func() SitePolicy {
		p := inheritedPolicy()
		p.ModSecurity = "On"
		p.Exceptions = []RuleException{}
		p.BlockedPaths = []string{}
		return p
	}
	return []PolicyTemplate{
		{ID: "generic", Name: "Generic web application", Description: "Conservative starting point: WAF blocking enabled, global thresholds and CrowdSec inherited. No automatic exclusions. Validate real application requests before rollout.", Builtin: true, Policy: policy()},
		{ID: "exchange-onprem", Name: "Exchange on-premises", Description: "Conservative security starting point, not an Exchange reverse-proxy configuration. No blanket exceptions for OWA, ECP, EWS, ActiveSync or Autodiscover. Validate client authentication, uploads and actual rule hits before adding narrowly scoped exceptions.", Builtin: true, Policy: policy()},
		{ID: "gitlab", Name: "GitLab", Description: "Conservative security starting point, not a GitLab proxy configuration. No blanket API, Git, registry or upload exclusions. Validate browser, Git-over-HTTP, API and registry traffic before adding narrowly scoped exceptions.", Builtin: true, Policy: policy()},
	}
}
func isBuiltinTemplate(id string) bool {
	for _, t := range builtinTemplates() {
		if t.ID == id {
			return true
		}
	}
	return false
}
func validateTemplate(t PolicyTemplate) error {
	if !templateID.MatchString(t.ID) || isBuiltinTemplate(t.ID) || t.Builtin || strings.TrimSpace(t.Name) == "" || utf8.RuneCountInString(t.Name) > 100 || utf8.RuneCountInString(t.Description) > 1000 {
		return ErrInvalid
	}
	for _, v := range []string{t.Name, t.Description} {
		if !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return ErrInvalid
		}
	}
	_, err := effectivePolicy(WAFConfig{Mode: "On", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}, t.Policy)
	return err
}
func (s *Service) templatePath() string {
	return filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "policy-templates.json")
}
func (s *Service) readTemplates() ([]PolicyTemplate, error) {
	path := s.templatePath()
	if err := safeFile(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []PolicyTemplate{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []PolicyTemplate
	if err = json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	if len(items) > 100 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range items {
		if err = validateTemplate(v); err != nil {
			return nil, err
		}
		if seen[v.ID] {
			return nil, ErrInvalid
		}
		seen[v.ID] = true
	}
	return items, nil
}
func (s *Service) Templates() ([]PolicyTemplate, error) {
	if err := s.waf(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.readTemplates()
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return append(builtinTemplates(), items...), nil
}
func (s *Service) SaveTemplate(t PolicyTemplate) error {
	if err := s.waf(); err != nil {
		return err
	}
	if err := validateTemplate(t); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.readTemplates()
	if err != nil {
		return err
	}
	found := false
	for i := range items {
		if items[i].ID == t.ID {
			items[i] = t
			found = true
		}
	}
	if !found {
		if len(items) >= 100 {
			return fmt.Errorf("%w: at most 100 custom templates", ErrInvalid)
		}
		items = append(items, t)
	}
	return s.writeTemplates(items)
}
func (s *Service) DeleteTemplate(id string) error {
	if err := s.waf(); err != nil {
		return err
	}
	if !templateID.MatchString(id) || isBuiltinTemplate(id) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.readTemplates()
	if err != nil {
		return err
	}
	for i, v := range items {
		if v.ID == id {
			return s.writeTemplates(append(items[:i], items[i+1:]...))
		}
	}
	return nil
}
func (s *Service) writeTemplates(items []PolicyTemplate) error {
	b, err := json.Marshal(items)
	if err != nil {
		return err
	}
	if len(b) > 65536 {
		return fmt.Errorf("%w: template storage limit exceeded", ErrInvalid)
	}
	return atomicWrite(s.templatePath(), b)
}
