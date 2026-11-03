package security_center

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type SharingStatus struct {
	Configured      bool   `json:"configured"`
	Enabled         *bool  `json:"enabled"`
	RuntimeVerified bool   `json:"runtime_verified"`
	Editable        bool   `json:"editable"`
	Message         string `json:"message"`
}

var sharingKeys = []string{"api", "server", "online_client", "sharing"}

func safeYAML(n *yaml.Node, depth int) bool {
	if depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if !safeYAML(child, depth+1) {
			return false
		}
	}
	return true
}
func readSharingDocument(path string) (*yaml.Node, []byte, error) {
	if err := safeFile(path); err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var n yaml.Node
	if d.Decode(&n) != nil || n.Kind != yaml.DocumentNode || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode || !safeYAML(&n, 0) {
		return nil, nil, errors.New("CrowdSec YAML is ambiguous or invalid")
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return nil, nil, errors.New("CrowdSec YAML must contain one document")
	}
	return &n, b, nil
}
func sharingValue(n *yaml.Node) (*bool, error) {
	cur := n.Content[0]
	for i, key := range sharingKeys {
		if cur.Kind != yaml.MappingNode {
			return nil, ErrInvalid
		}
		var next *yaml.Node
		for j := 0; j < len(cur.Content); j += 2 {
			if cur.Content[j].Value == key {
				next = cur.Content[j+1]
				break
			}
		}
		if next == nil {
			return nil, nil
		}
		cur = next
		if i == len(sharingKeys)-1 {
			if cur.Tag != "!!bool" || (cur.Value != "true" && cur.Value != "false") {
				return nil, ErrInvalid
			}
			v := cur.Value == "true"
			return &v, nil
		}
	}
	return nil, nil
}
func setSharingValue(n *yaml.Node, enabled bool) error {
	cur := n.Content[0]
	for i, key := range sharingKeys {
		if cur.Kind != yaml.MappingNode {
			return ErrInvalid
		}
		var next *yaml.Node
		for j := 0; j < len(cur.Content); j += 2 {
			if cur.Content[j].Value == key {
				next = cur.Content[j+1]
				break
			}
		}
		if next == nil {
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			cur.Content = append(cur.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, next)
		}
		if i == len(sharingKeys)-1 {
			next.Kind = yaml.ScalarNode
			next.Tag = "!!bool"
			next.Value = strconv.FormatBool(enabled)
			next.Content = nil
			return nil
		}
		cur = next
	}
	return ErrInvalid
}
func (s *Service) sharingDocument() (*yaml.Node, []byte, string, *bool, error) {
	path := s.Config.SharingConfigPath
	base, old, err := readSharingDocument(path)
	if err != nil {
		return nil, nil, "", nil, err
	}
	value, err := sharingValue(base)
	if err != nil {
		return nil, nil, "", nil, err
	}
	local := path + ".local"
	if _, err = os.Lstat(local); os.IsNotExist(err) {
		return base, old, path, value, nil
	} else if err != nil {
		return nil, nil, "", nil, err
	}
	overlay, b, err := readSharingDocument(local)
	if err != nil {
		return nil, nil, "", nil, err
	}
	override, err := sharingValue(overlay)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if override != nil {
		value = override
	}
	return overlay, b, local, value, nil
}
func (s *Service) Sharing() SharingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := SharingStatus{Message: "Community signal sharing is unknown; no engine configuration integration is configured"}
	if s.crowdsec() != nil {
		return v
	}
	if s.remoteControlConfigured() {
		status, err := s.remoteSharing(context.Background(), nil)
		if err != nil {
			v.Message = "Community signal sharing is unknown: central engine control is unavailable"
			return v
		}
		return status
	}
	if s.Config.SharingConfigPath == "" {
		return v
	}
	_, _, _, enabled, err := s.sharingDocument()
	if err != nil {
		v.Message = "Community signal sharing is unknown: engine configuration could not be safely read"
		return v
	}
	v.Configured = true
	v.Enabled = enabled
	v.Editable = filepath.IsAbs(s.Config.SharingValidatePath) && filepath.IsAbs(s.Config.CrowdSecReloadPath)
	v.Message = "Configured engine sharing value; live engine state is not verified. This controls engine alerts, not every blocked HTTP request."
	if enabled == nil {
		v.Message = "No explicit sharing value in effective engine configuration; current behavior is unknown"
	}
	return v
}
func (s *Service) SetSharing(ctx context.Context, enabled bool) error {
	if err := s.crowdsec(); err != nil {
		return err
	}
	if s.remoteControlConfigured() {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, err := s.remoteSharing(ctx, &enabled)
		return err
	}
	if !filepath.IsAbs(s.Config.SharingConfigPath) || !filepath.IsAbs(s.Config.SharingValidatePath) || !filepath.IsAbs(s.Config.CrowdSecReloadPath) {
		return ErrDisabled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, old, path, _, err := s.sharingDocument()
	if err != nil {
		return errors.New("CrowdSec engine configuration could not be safely read")
	}
	if err = setSharingValue(n, enabled); err != nil {
		return err
	}
	b, err := yaml.Marshal(n)
	if err != nil || len(b) > 65536 {
		return ErrInvalid
	}
	restore := func() error { return atomicWrite(path, old) }
	if err = atomicWrite(path, b); err != nil {
		if restore() != nil {
			return errors.New("sharing save and rollback failed; manual recovery required")
		}
		return errors.New("sharing save failed; prior configuration restored")
	}
	if _, err = s.Run(ctx, s.Config.SharingValidatePath); err != nil {
		if restore() != nil {
			return errors.New("sharing validation and rollback failed; manual recovery required")
		}
		return errors.New("sharing validation failed; prior configuration restored")
	}
	if _, err = s.Run(ctx, s.Config.CrowdSecReloadPath); err != nil {
		if restore() != nil {
			return errors.New("sharing reload and rollback failed; manual recovery required")
		}
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err = s.Run(recovery, s.Config.CrowdSecReloadPath); err != nil {
			return errors.New("sharing restored but recovery reload failed; manual recovery required")
		}
		return errors.New("sharing reload failed; prior configuration restored and recovery reload requested")
	}
	return nil
}
