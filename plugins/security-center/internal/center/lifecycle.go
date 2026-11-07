package security_center

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	ngxconfig "github.com/tufanbarisyildirim/gonginx/config"
	"github.com/tufanbarisyildirim/gonginx/dumper"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

// detach removes only this plugin's exact includes; every other directive stays.
func detach(content, snippet string) (string, error) {
	p, err := parser.NewStringParser(content, parser.WithSkipValidDirectivesErr()).Parse()
	if err != nil {
		return "", err
	}
	changed := false
	for _, d := range p.GetDirectives() {
		if d.GetName() != "server" {
			continue
		}
		b, ok := d.GetBlock().(*ngxconfig.Block)
		if !ok {
			return "", ErrInvalid
		}
		kept := b.Directives[:0]
		for _, c := range b.Directives {
			if c.GetName() == "include" && len(c.GetParameters()) == 1 && c.GetParameters()[0].Value == snippet {
				changed = true
				continue
			}
			kept = append(kept, c)
		}
		b.Directives = kept
	}
	if !changed {
		return content, nil
	}
	return dumper.DumpConfig(p, dumper.IndentedStyle), nil
}
func (s *Service) states() ([]SiteState, error) {
	dir := filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(entries) > 6000 {
		return nil, ErrInvalid
	}
	states := []SiteState{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err = safeFile(path); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var state SiteState
		if err = json.Unmarshal(b, &state); err != nil {
			return nil, err
		}
		expected, _, _ := s.sitePaths(state.Name)
		if expected != path || state.Revision <= 0 {
			return nil, ErrInvalid
		}
		states = append(states, state)
	}
	return states, nil
}

// Deactivate is explicit only. It never erases desired policies, templates or bans.
func (s *Service) Deactivate(ctx context.Context) (err error) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	s.bulkDisabled = true
	defer func() {
		if err != nil {
			s.bulkDisabled = false
		}
	}()
	if err := s.cancelBulkBeforeDeactivate(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	states, err := s.states()
	if err != nil {
		return err
	}
	// An installed plugin with no owned sites has nothing to detach. Existing
	// authentication/security hooks belong to the operator, not this lifecycle.
	if len(states) == 0 {
		return nil
	}
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil {
		return err
	}
	if err = s.checkTopology(dump); err != nil {
		return err
	}
	changes := []fileChange{}
	for _, state := range states {
		path, err := s.sitePath(state.Name)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _, snippet := s.sitePaths(state.Name)
		updated, err := detach(string(b), snippet)
		if err != nil {
			return err
		}
		if updated != string(b) {
			s.remember(path, b, false)
			changes = append(changes, fileChange{path, []byte(updated)})
		}
	}
	if len(changes) == 0 {
		return nil
	}
	return s.applyFiles(ctx, changes)
}

// Activate restores saved policies after explicit disable, without revising ownership.
func (s *Service) Activate(ctx context.Context) (err error) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	defer func() {
		if err == nil {
			s.bulkDisabled = false
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	states, err := s.states()
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return nil
	}
	global, err := s.readWAF()
	if err != nil {
		return err
	}
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil {
		return err
	}
	if err = s.checkTopology(dump); err != nil {
		return err
	}
	changes := []fileChange{}
	for _, state := range states {
		c, err := s.stateChanges(global, state)
		if err != nil {
			return err
		}
		changes = append(changes, c...)
	}
	return s.applyFiles(ctx, changes)
}

// Migrate adopts the legacy built-in's marked files. Sources remain untouched as
// a backup; active includes and copied state change together through the host.
func (s *Service) Migrate(ctx context.Context, legacyRoot string) error {
	if legacyRoot == filepath.Dir(s.Config.ModSecurityPath) {
		return nil
	}
	if _, err := os.Stat(s.Config.ModSecurityPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	old := New(s.Config)
	old.Config.ModSecurityPath = filepath.Join(legacyRoot, "modsecurity.conf")
	old.SiteResolver = s.SiteResolver
	old.SiteLister = s.SiteLister
	old.Run = s.Run
	if err := safeFile(old.Config.ModSecurityPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	_, err := readManaged(old.Config.ModSecurityPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	global, err := old.readWAF()
	if err != nil {
		return err
	}
	dump, err := old.Run(ctx, old.Config.NginxPath, "-T")
	if err != nil {
		return err
	}
	if err = old.checkTopology(dump); err != nil {
		return err
	}
	states, err := old.states()
	if err != nil {
		return err
	}
	if err = s.prepareSiteDir(); err != nil {
		return err
	}
	data, err := s.render(global)
	if err != nil {
		return err
	}
	changes := []fileChange{{s.Config.ModSecurityPath, data}}
	for _, state := range states {
		path, err := s.sitePath(state.Name)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _, oldSnippet := old.sitePaths(state.Name)
		_, _, newSnippet := s.sitePaths(state.Name)
		if err := safeFile(oldSnippet); err != nil {
			return err
		}
		oldBytes, err := os.ReadFile(oldSnippet)
		if err != nil || !strings.HasPrefix(string(oldBytes), snippetMarker) {
			return errors.New("legacy security snippet ownership cannot be verified")
		}
		// Generate current policies, then replace the existing legacy include rather
		// than leaving two complete CRS files attached to the same server.
		c, err := s.stateChanges(global, state)
		if err != nil {
			return err
		}
		for i := range c {
			if c[i].path == path {
				clean, err := detach(string(b), oldSnippet)
				if err != nil {
					return err
				}
				updated, err := configureSite(clean, newSnippet)
				if err != nil {
					return err
				}
				c[i].data = []byte(updated)
			}
		}
		changes = append(changes, c...)
	}
	if items, err := old.readTemplates(); err != nil {
		return err
	} else if len(items) > 0 {
		b, _ := json.Marshal(items)
		changes = append(changes, fileChange{s.templatePath(), b})
	}
	return s.applyFiles(ctx, changes)
}
