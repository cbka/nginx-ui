package security_center

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	ngxconfig "github.com/tufanbarisyildirim/gonginx/config"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

// checkTopology follows includes in their actual context. Foreign server hooks
// are isolated; inherited http hooks and hooks anywhere in a managed server
// (including nested locations/includes) remain conflicts. Unresolved includes
// fail closed instead of guessing their inheritance.
func (s *Service) checkTopology(dump []byte, additionalSites ...string) error {
	conflict := errors.New("existing inherited or target-site security hooks require manual integration")
	invalid := errors.New("cannot safely resolve Nginx security include topology")
	sections := strings.Split(string(dump), "# configuration file ")
	if len(sections) < 2 {
		return invalid
	}
	canonical := func(path string) string {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return resolved
		}
		return filepath.Clean(path)
	}
	files := map[string]ngxconfig.IBlock{}
	aliases := map[string]string{}
	managed := map[string]bool{}
	root := ""
	for _, section := range sections[1:] {
		line, body, ok := strings.Cut(section, "\n")
		if !ok {
			return invalid
		}
		path := strings.TrimSuffix(strings.TrimSpace(line), ":")
		if !filepath.IsAbs(path) {
			return invalid
		}
		key := canonical(path)
		if root == "" {
			root = path
		}
		aliases[path] = key
		if strings.HasPrefix(path, filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites")+string(os.PathSeparator)) && strings.HasSuffix(path, ".nginx.conf") {
			b, err := os.ReadFile(path)
			if err != nil || !strings.HasPrefix(string(b), snippetMarker) || strings.TrimRight(string(b), "\n") != strings.TrimRight(body, "\n") {
				return errors.New("unowned or changed security snippet encountered")
			}
			managed[key] = true
		}
		parsed, err := parser.NewStringParser(body, parser.WithSkipValidDirectivesErr()).Parse()
		if err != nil {
			return invalid
		}
		files[key] = parsed.Block
	}
	states, err := s.states()
	if err != nil {
		return err
	}
	for _, state := range states {
		additionalSites = append(additionalSites, state.Name)
	}
	targets := map[string]bool{}
	for _, name := range additionalSites {
		path, err := s.sitePath(name)
		if err != nil {
			return err
		}
		key := canonical(path)
		targets[key] = true
		if _, ok := files[key]; !ok {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			parsed, err := parser.NewStringParser(string(b), parser.WithSkipValidDirectivesErr()).Parse()
			if err != nil {
				return invalid
			}
			files[key] = parsed.Block
		}
	}
	visited := map[string]bool{}
	active := map[string]bool{}
	steps := 0
	var walkFile func(string, bool, bool, int) error
	var walkBlock func(ngxconfig.IBlock, bool, bool, bool, int) error
	walkFile = func(key string, inServer, target bool, depth int) error {
		steps++
		if depth > 64 || steps > 20000 || active[key] {
			return invalid
		}
		block, ok := files[key]
		if !ok {
			return invalid
		}
		visited[key] = true
		if managed[key] {
			if !inServer || !target {
				return conflict
			}
			return nil
		}
		active[key] = true
		defer delete(active, key)
		return walkBlock(block, inServer, target, targets[key], depth+1)
	}
	walkBlock = func(block ngxconfig.IBlock, inServer, target, targetSource bool, depth int) error {
		if depth > 64 {
			return invalid
		}
		for _, d := range block.GetDirectives() {
			if sensitiveDirective(d.GetName()) && (!inServer || target) {
				return conflict
			}
			if d.GetName() == "include" {
				params := d.GetParameters()
				if len(params) != 1 || strings.Contains(params[0].Value, "$") {
					return invalid
				}
				pattern := params[0].Value
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(root), pattern)
				}
				matches := map[string]bool{}
				for path, key := range aliases {
					match, err := filepath.Match(pattern, path)
					if err != nil {
						return invalid
					}
					if match {
						matches[key] = true
					}
				}
				if _, ok := files[canonical(pattern)]; ok {
					matches[canonical(pattern)] = true
				}
				// A disabled site's glob may expand to files absent from -T.
				// Never interpret that as an empty include and miss its hooks.
				diskMatches, err := filepath.Glob(pattern)
				if err != nil {
					return invalid
				}
				for _, path := range diskMatches {
					key := canonical(path)
					if _, ok := files[key]; !ok {
						return invalid
					}
					matches[key] = true
				}
				if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
					return invalid
				}
				for key := range matches {
					if err := walkFile(key, inServer, target, depth+1); err != nil {
						return err
					}
				}
			}
			if child := d.GetBlock(); child != nil {
				nextServer, nextTarget := inServer, target
				if d.GetName() == "server" {
					nextServer, nextTarget = true, target || targetSource
				}
				if err := walkBlock(child, nextServer, nextTarget, targetSource, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walkFile(canonical(root), false, false, 0); err != nil {
		return err
	}
	for key := range targets {
		if !visited[key] {
			if err := walkFile(key, false, false, 0); err != nil {
				return err
			}
		}
	}
	// A dump section not reached through the root cannot establish inheritance.
	for key := range files {
		if !visited[key] {
			return invalid
		}
	}
	return nil
}
