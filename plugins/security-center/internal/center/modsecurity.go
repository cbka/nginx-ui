package security_center

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const marker = "# nginx-ui-security-center: "

type WAFConfig struct {
	CrowdSecEnabled   bool   `json:"crowdsec_enabled"`
	Mode              string `json:"mode"`
	ParanoiaLevel     int    `json:"paranoia_level"`
	InboundThreshold  int    `json:"inbound_threshold"`
	OutboundThreshold int    `json:"outbound_threshold"`
	ExcludedRuleIDs   []int  `json:"excluded_rule_ids"`
}

func (c WAFConfig) Validate() error {
	if c.Mode != "Off" && c.Mode != "DetectionOnly" && c.Mode != "On" {
		return ErrInvalid
	}
	if c.ParanoiaLevel < 1 || c.ParanoiaLevel > 4 || c.InboundThreshold < 1 || c.InboundThreshold > 1000 || c.OutboundThreshold < 1 || c.OutboundThreshold > 1000 || len(c.ExcludedRuleIDs) > 200 {
		return ErrInvalid
	}
	seen := map[int]bool{}
	for _, id := range c.ExcludedRuleIDs {
		if id < 900000 || id > 999999 || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func (s *Service) waf() error {
	if !s.Config.Enabled || !s.Config.ModSecurityEnabled {
		return ErrDisabled
	}
	return nil
}

// All parent components must be real directories. This API never follows symlinks
// or replaces unmanaged configuration files.
func safeFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if parent == "/" {
			break
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return ErrInvalid
	}
	return nil
}
func readManaged(path string) ([]byte, error) {
	if err := safeFile(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(b), marker) {
		return nil, errors.New("refusing to replace unmanaged ModSecurity configuration")
	}
	return b, nil
}
func (s *Service) ReadWAF() (WAFConfig, error) {
	if err := s.waf(); err != nil {
		return WAFConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readWAF()
}
func (s *Service) readWAF() (WAFConfig, error) {
	b, err := readManaged(s.Config.ModSecurityPath)
	if os.IsNotExist(err) {
		return WAFConfig{Mode: "DetectionOnly", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, ExcludedRuleIDs: []int{}}, nil
	}
	if err != nil {
		return WAFConfig{}, err
	}
	var c WAFConfig
	line := strings.SplitN(string(b), "\n", 2)[0]
	if err = json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func (s *Service) render(c WAFConfig) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	for _, path := range []string{s.Config.BaseConfig, s.Config.CRSSetup, s.Config.CRSRules} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\"\r\n\x00\\") {
			return nil, ErrInvalid
		}
	}
	j, _ := json.Marshal(c)
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\nInclude \"%s\"\nSecRuleEngine %s\nInclude \"%s\"\n", marker, j, s.Config.BaseConfig, c.Mode, s.Config.CRSSetup)
	fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,nolog,t:none,setvar:tx.paranoia_level=%d\"\n", c.ParanoiaLevel)
	fmt.Fprintf(&b, "SecAction \"id:900120,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", c.InboundThreshold, c.OutboundThreshold)
	fmt.Fprintf(&b, "Include \"%s\"\n", s.Config.CRSRules)
	for _, id := range c.ExcludedRuleIDs {
		b.WriteString("SecRuleRemoveById " + strconv.Itoa(id) + "\n")
	}
	return []byte(b.String()), nil
}
func atomicWrite(path string, b []byte) error {
	if err := safeFile(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".security-center-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	mode := os.FileMode(0640)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Service) ApplyWAF(ctx context.Context, c WAFConfig) error { return s.applyGlobal(ctx, c) }

// RuntimeReady verifies that at least one managed site snippet participates in Nginx.
// It does not claim that a request has been inspected or blocked.
func (s *Service) RuntimeReady(ctx context.Context) bool {
	if s.waf() != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil || s.checkTopology(dump) != nil {
		return false
	}
	prefix := filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites") + string(os.PathSeparator)
	return strings.Contains(string(dump), "# configuration file "+prefix)
}
