package security_center

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	ngxconfig "github.com/tufanbarisyildirim/gonginx/config"
	"github.com/tufanbarisyildirim/gonginx/dumper"
	"github.com/tufanbarisyildirim/gonginx/parser"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const accessHook = "/usr/local/lua/nginx-ui/security-access.lua"
const snippetMarker = "# nginx-ui-security-center managed site\n"

type RuleException struct {
	RuleID    int    `json:"rule_id"`
	Path      string `json:"path,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}
type SitePolicy struct {
	ModSecurityAllowlist []string        `json:"modsecurity_allowlist,omitempty"`
	CrowdSecAllowlist    []string        `json:"crowdsec_allowlist,omitempty"`
	Exceptions           []RuleException `json:"exceptions"`
	BlockedPaths         []string        `json:"blocked_paths"`
	ModSecurity          string          `json:"modsecurity"`
	CrowdSec             string          `json:"crowdsec"`
	ParanoiaLevel        *int            `json:"paranoia_level"`
	InboundThreshold     *int            `json:"inbound_threshold"`
	OutboundThreshold    *int            `json:"outbound_threshold"`
	ExcludedRuleIDs      []int           `json:"excluded_rule_ids"`
}
type SiteState struct {
	Revision       int64      `json:"revision,string"`
	Owner          string     `json:"owner"`
	Replica        bool       `json:"replica"`
	GlobalSnapshot *WAFConfig `json:"global_snapshot,omitempty"`
	ContentHash    string     `json:"content_hash,omitempty"`
	Name           string     `json:"name"`
	Policy         SitePolicy `json:"policy"`
}
type EffectivePolicy struct {
	ModSecurity WAFConfig `json:"modsecurity"`
	CrowdSec    bool      `json:"crowdsec"`
}
type SiteResponse struct {
	SiteState
	Effective EffectivePolicy `json:"effective"`
}
type SiteEntry struct {
	Name        string   `json:"name"`
	ServerNames []string `json:"server_names"`
}

func inheritedPolicy() SitePolicy {
	return SitePolicy{ModSecurity: "inherit", CrowdSec: "inherit", ExcludedRuleIDs: []int{}}
}
func resolveProductionSite(name string) (string, error) {
	return "", errors.New("host site resolver is not initialized")
}
func listProductionSites() ([]string, error) {
	return nil, errors.New("host site inventory is not initialized")
}
func (s *Service) sitePaths(name string) (string, string, string) {
	hash := sha256.Sum256([]byte(name))
	base := filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites", hex.EncodeToString(hash[:]))
	return base + ".json", base + ".rules.conf", base + ".nginx.conf"
}
func (s *Service) sitePath(name string) (string, error) {
	if name == "" || name == "." || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", ErrInvalid
	}
	path, err := s.SiteResolver(name)
	if err != nil {
		return "", err
	}
	if err = safeFile(path); err != nil {
		return "", err
	}
	if _, err = os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}
func (s *Service) readPolicy(name string) (SiteState, error) {
	state := SiteState{Name: name, Policy: inheritedPolicy()}
	path, _, _ := s.sitePaths(name)
	if err := safeFile(path); err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return state, err
	}
	if state.Name != name {
		return state, ErrInvalid
	}
	return state, nil
}
func effectivePolicy(global WAFConfig, p SitePolicy) (EffectivePolicy, error) {
	if err := validateLocalRules(p); err != nil {
		return EffectivePolicy{}, err
	}
	c := global
	var err error
	if c.ModSecurityAllowlist, err = mergeIPAllowlist(global.ModSecurityAllowlist, p.ModSecurityAllowlist); err != nil {
		return EffectivePolicy{}, err
	}
	if c.CrowdSecAllowlist, err = mergeIPAllowlist(global.CrowdSecAllowlist, p.CrowdSecAllowlist); err != nil {
		return EffectivePolicy{}, err
	}
	if p.ModSecurity != "inherit" {
		c.Mode = p.ModSecurity
	}
	cs := global.CrowdSecEnabled
	switch p.CrowdSec {
	case "inherit":
	case "on":
		cs = true
	case "off":
		cs = false
	default:
		return EffectivePolicy{}, ErrInvalid
	}
	if p.ParanoiaLevel != nil {
		c.ParanoiaLevel = *p.ParanoiaLevel
	}
	if p.InboundThreshold != nil {
		c.InboundThreshold = *p.InboundThreshold
	}
	if p.OutboundThreshold != nil {
		c.OutboundThreshold = *p.OutboundThreshold
	}
	// Validate local IDs independently; effective exclusions are an additive union.
	local := c
	local.ExcludedRuleIDs = p.ExcludedRuleIDs
	if err := local.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	seen := map[int]bool{}
	c.ExcludedRuleIDs = []int{}
	for _, ids := range [][]int{global.ExcludedRuleIDs, p.ExcludedRuleIDs} {
		for _, id := range ids {
			if !seen[id] {
				c.ExcludedRuleIDs = append(c.ExcludedRuleIDs, id)
				seen[id] = true
			}
		}
	}
	sort.Ints(c.ExcludedRuleIDs)
	if err := c.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	return EffectivePolicy{ModSecurity: c, CrowdSec: cs}, nil
}
func (s *Service) GetSite(name string) (SiteResponse, error) {
	if err := s.waf(); err != nil {
		return SiteResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	if _, err := s.sitePath(name); err != nil {
		return SiteResponse{}, err
	}
	state, err := s.readPolicy(name)
	if err != nil {
		return SiteResponse{}, err
	}
	global, err := s.readWAF()
	if err != nil {
		return SiteResponse{}, err
	}
	if state.Replica && state.GlobalSnapshot != nil {
		global = *state.GlobalSnapshot
	}
	effective, err := effectivePolicy(global, state.Policy)
	return SiteResponse{SiteState: state, Effective: effective}, err
}
func (s *Service) Sites() ([]SiteEntry, error) {
	if err := s.waf(); err != nil {
		return nil, err
	}
	names, err := s.SiteLister()
	if err != nil {
		return nil, err
	}
	if len(names) > 2000 {
		return nil, errors.New("site inventory exceeds safety limit")
	}
	items := []SiteEntry{}
	for _, name := range names {
		path, err := s.sitePath(name)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		parsed, err := parser.NewStringParser(string(b), parser.WithSkipValidDirectivesErr()).Parse()
		if err != nil {
			continue
		}
		entry := SiteEntry{Name: name, ServerNames: []string{}}
		servers := 0
		for _, server := range parsed.GetDirectives() {
			if server.GetName() != "server" {
				continue
			}
			servers++
			for _, d := range server.GetBlock().GetDirectives() {
				if d.GetName() == "server_name" {
					for _, p := range d.GetParameters() {
						entry.ServerNames = append(entry.ServerNames, p.Value)
					}
				}
			}
		}
		if servers > 0 {
			items = append(items, entry)
		}
	}
	return items, nil
}
func sensitiveDirective(name string) bool {
	return strings.HasPrefix(name, "modsecurity") || strings.HasPrefix(name, "access_by_lua") || name == "set_by_lua"
}
func rejectSensitive(block ngxconfig.IBlock) error {
	for _, d := range block.GetDirectives() {
		if sensitiveDirective(d.GetName()) {
			return errors.New("existing ModSecurity or Lua access directives require manual integration before managing this site")
		}
		if d.GetBlock() != nil {
			if err := rejectSensitive(d.GetBlock()); err != nil {
				return err
			}
		}
	}
	return nil
}
func configureSite(content, snippet string) (string, error) {
	parsed, err := parser.NewStringParser(content, parser.WithSkipValidDirectivesErr()).Parse()
	if err != nil {
		return "", err
	}
	if err = rejectSensitive(parsed.Block); err != nil {
		return "", err
	}
	count := 0
	changed := false
	for _, d := range parsed.GetDirectives() {
		if d.GetName() != "server" {
			continue
		}
		block, ok := d.GetBlock().(*ngxconfig.Block)
		if !ok {
			return "", ErrInvalid
		}
		count++
		ownedIncludes := 0
		for _, child := range block.Directives {
			if child.GetName() == "include" && len(child.GetParameters()) == 1 && child.GetParameters()[0].Value == snippet {
				ownedIncludes++
			}
		}
		if ownedIncludes > 1 {
			return "", errors.New("duplicate managed security includes require repair")
		}
		if ownedIncludes == 1 {
			continue
		}
		changed = true
		block.Directives = append(block.Directives, &ngxconfig.Directive{Name: "include", Parameters: []ngxconfig.Parameter{{Value: snippet}}, Comment: []string{"# Nginx UI managed site security"}})
	}
	if count == 0 {
		return "", errors.New("site contains no top-level HTTP server blocks")
	}
	if !changed {
		return content, nil
	}
	return dumper.DumpConfig(parsed, dumper.IndentedStyle), nil
}

type fileChange struct {
	path string
	data []byte
}
type fileSnapshot struct {
	path    string
	data    []byte
	missing bool
}

func (s *Service) applyFiles(ctx context.Context, changes []fileChange) error {
	if s.Transaction != nil {
		return s.commit(ctx, changes)
	}

	snapshots := []fileSnapshot{}
	for _, change := range changes {
		if err := safeFile(change.path); err != nil {
			return err
		}
		b, err := os.ReadFile(change.path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		snapshots = append(snapshots, fileSnapshot{change.path, b, os.IsNotExist(err)})
	}
	restore := func() error {
		var failures []error
		for i := len(snapshots) - 1; i >= 0; i-- {
			snap := snapshots[i]
			var err error
			if snap.missing {
				err = os.Remove(snap.path)
				if os.IsNotExist(err) {
					err = nil
				}
			} else {
				err = atomicWrite(snap.path, snap.data)
			}
			if err != nil {
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}
	for _, change := range changes {
		if err := atomicWrite(change.path, change.data); err != nil {
			if restore() != nil {
				return errors.New("security write and rollback failed; manual recovery required")
			}
			return err
		}
	}
	if _, err := s.Run(ctx, s.Config.NginxPath, "-t"); err != nil {
		if restore() != nil {
			return errors.New("validation and rollback failed; manual recovery required")
		}
		return errors.New("Nginx validation failed; all security changes restored")
	}
	if _, err := s.Run(ctx, s.Config.NginxPath, "-s", "reload"); err != nil {
		if restore() != nil {
			return errors.New("reload and rollback failed; manual recovery required")
		}
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err = s.Run(recovery, s.Config.NginxPath, "-s", "reload"); err != nil {
			return errors.New("files restored but recovery reload failed; manual recovery required")
		}
		return errors.New("reload failed; all files restored and recovery reload requested")
	}
	return nil
}
func (s *Service) stateChanges(global WAFConfig, state SiteState) ([]fileChange, error) {
	path, err := s.sitePath(state.Name)
	if err != nil {
		return nil, err
	}
	if state.Replica && state.GlobalSnapshot != nil {
		global = *state.GlobalSnapshot
	}
	effective, err := effectivePolicy(global, state.Policy)
	if err != nil {
		return nil, err
	}
	if effective.CrowdSec && !s.Config.CrowdSecEnabled {
		return nil, errors.New("CrowdSec component is not configured")
	}
	meta, rules, snippet := s.sitePaths(state.Name)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s.remember(path, b, false)
	updated, err := configureSite(string(b), snippet)
	if err != nil {
		return nil, err
	}
	ruleData, err := s.render(effective.ModSecurity)
	if err != nil {
		return nil, err
	}
	siteID := strings.TrimSuffix(filepath.Base(meta), ".json")
	ruleData = append(ruleData, []byte("SecAuditLog /var/log/nginx/modsecurity/"+siteID+".json\n")...)
	localRules := renderLocalRules(state.Policy)
	ruleData = []byte(strings.Replace(string(ruleData), fmt.Sprintf("Include \"%s\"", s.Config.CRSRules), localRules+fmt.Sprintf("Include \"%s\"", s.Config.CRSRules), 1))
	flag := "0"
	if effective.CrowdSec {
		flag = "1"
	}
	mode := "on"
	if effective.ModSecurity.Mode == "Off" {
		mode = "off"
	}
	snippetData := fmt.Sprintf("%smodsecurity %s;\nmodsecurity_rules_file %s;\nset $nginx_ui_crowdsec_enabled %s;\nset $nginx_ui_security_site_id %s;\nset $nginx_ui_crowdsec_allowlist \"%s\";\naccess_by_lua_file %s;\n", snippetMarker, mode, rules, flag, siteID, strings.Join(effective.ModSecurity.CrowdSecAllowlist, ","), accessHook)
	for _, owned := range []struct{ path, prefix string }{{rules, marker}, {snippet, snippetMarker}} {
		if err := safeFile(owned.path); err != nil {
			return nil, err
		}
		existing, readErr := os.ReadFile(owned.path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return nil, readErr
		}
		if readErr == nil && !strings.HasPrefix(string(existing), owned.prefix) {
			return nil, errors.New("refusing to overwrite unowned generated security file")
		}
	}
	if _, err := s.readPolicy(state.Name); err != nil {
		return nil, err
	}
	metaData, _ := json.Marshal(state)
	return []fileChange{{rules, ruleData}, {snippet, []byte(snippetData)}, {meta, metaData}, {path, []byte(updated)}}, nil
}
func (s *Service) prepareSiteDir() error {
	dir := filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites")
	if err := safeFile(filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "probe")); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0750); err != nil && !os.IsExist(err) {
		return err
	}
	return safeFile(filepath.Join(dir, "probe"))
}
func (s *Service) ApplySite(ctx context.Context, name string, p SitePolicy) (SiteResponse, error) {
	if err := s.waf(); err != nil {
		return SiteResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	if _, err := s.sitePath(name); err != nil {
		return SiteResponse{}, err
	}
	global, err := s.readWAF()
	if err != nil {
		return SiteResponse{}, err
	}
	oldState, err := s.readPolicy(name)
	if err != nil {
		return SiteResponse{}, err
	}
	if oldState.Replica {
		return SiteResponse{}, errors.New("site policy is owned by its paired controller; edit it at the source")
	}
	if s.InstanceID == "" {
		return SiteResponse{}, errors.New("node instance identity is unavailable")
	}
	state := SiteState{Name: name, Policy: p, Owner: s.InstanceID, Revision: nextRevision(oldState.Revision)}
	effective, err := effectivePolicy(global, p)
	if err != nil {
		return SiteResponse{}, err
	}
	if err = s.prepareSiteDir(); err != nil {
		return SiteResponse{}, err
	}
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil {
		return SiteResponse{}, err
	}
	if err = s.checkTopology(dump, name); err != nil {
		return SiteResponse{}, err
	}
	changes, err := s.stateChanges(global, state)
	if err != nil {
		return SiteResponse{}, err
	}
	if err = s.applyFiles(ctx, changes); err != nil {
		return SiteResponse{}, err
	}
	return SiteResponse{SiteState: state, Effective: effective}, nil
}
func (s *Service) applyGlobal(ctx context.Context, c WAFConfig) error {
	if err := s.waf(); err != nil {
		return err
	}
	data, err := s.render(c)
	if err != nil {
		return err
	}
	if c.CrowdSecEnabled && !s.Config.CrowdSecEnabled {
		return errors.New("CrowdSec component is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	old, oldErr := readManaged(s.Config.ModSecurityPath)
	if err = oldErr; err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = s.prepareSiteDir(); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites"))
	if err != nil {
		return err
	}
	changes := []fileChange{{s.Config.ModSecurityPath, data}}
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if count++; count > 2000 {
			return errors.New("managed site count exceeds safety limit")
		}
		path := filepath.Join(filepath.Dir(s.Config.ModSecurityPath), "sites", e.Name())
		if err = safeFile(path); err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var state SiteState
		if err = json.Unmarshal(b, &state); err != nil {
			return err
		}
		expected, _, _ := s.sitePaths(state.Name)
		if expected != path {
			return ErrInvalid
		}
		if state.Replica {
			continue
		}
		state.Owner = s.InstanceID
		state.Revision = nextRevision(state.Revision)
		siteChanges, err := s.stateChanges(c, state)
		if err != nil {
			return err
		}
		changes = append(changes, siteChanges...)
	}
	if len(changes) == 1 {
		if err := atomicWrite(s.Config.ModSecurityPath, data); err != nil {
			var restoreErr error
			if os.IsNotExist(oldErr) {
				restoreErr = os.Remove(s.Config.ModSecurityPath)
				if os.IsNotExist(restoreErr) {
					restoreErr = nil
				}
			} else {
				restoreErr = atomicWrite(s.Config.ModSecurityPath, old)
			}
			if restoreErr != nil {
				return errors.New("global defaults write and rollback failed; manual recovery required")
			}
			return err
		}
		return nil
	}
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil {
		return err
	}
	if err = s.checkTopology(dump); err != nil {
		return err
	}
	return s.applyFiles(ctx, changes)
}

var literalPath = regexp.MustCompile(`^/[a-zA-Z0-9/_.,~!$&()*+:=@%-]*$`)
var argumentName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,100}$`)

func validateLocalRules(p SitePolicy) error {
	if len(p.Exceptions) > 100 || len(p.BlockedPaths) > 100 {
		return ErrInvalid
	}
	for _, e := range p.Exceptions {
		if e.RuleID < 900000 || e.RuleID > 999999 || (e.Path == "" && e.Parameter == "") {
			return ErrInvalid
		}
		if e.Path != "" && (len(e.Path) > 512 || !literalPath.MatchString(e.Path)) {
			return ErrInvalid
		}
		if e.Parameter != "" && !argumentName.MatchString(e.Parameter) {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, path := range p.BlockedPaths {
		if len(path) > 512 || !literalPath.MatchString(path) || seen[path] {
			return ErrInvalid
		}
		seen[path] = true
	}
	return nil
}
func renderLocalRules(p SitePolicy) string {
	var b strings.Builder
	for i, e := range p.Exceptions {
		control := fmt.Sprintf("ctl:ruleRemoveById=%d", e.RuleID)
		if e.Parameter != "" {
			control = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", e.RuleID, e.Parameter)
		}
		actions := fmt.Sprintf("id:%d,phase:1,pass,nolog,t:none,%s", 2000000+i, control)
		if e.Path == "" {
			fmt.Fprintf(&b, "SecAction \"%s\"\n", actions)
		} else {
			fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@streq %s\" \"%s\"\n", e.Path, actions)
		}
	}
	for i, path := range p.BlockedPaths {
		fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@streq %s\" \"id:%d,phase:1,deny,status:403,log,t:none,msg:'Nginx UI site path block'\"\n", path, 2100000+i)
	}
	return b.String()
}
