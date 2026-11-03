package security_center

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrDisabled = errors.New("security component is not enabled")
var ErrInvalid = errors.New("invalid security configuration")

type Runner func(context.Context, string, ...string) ([]byte, error)
type Service struct {
	Config       Config
	Run          Runner
	mu           sync.Mutex
	InstanceID   string
	SiteResolver func(string) (string, error)
	SiteLister   func() ([]string, error)
	Transaction  func(context.Context, []Change) error
	expected     map[string]string
}

// Output is bounded even when a privileged external tool misbehaves.
type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2<<20 {
		return 0, errors.New("command output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func Execute(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	var out limitedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("security command timed out or request was cancelled")
		}
		return nil, errors.New("security command failed; run server-side configuration checks for details")
	}
	return out.Bytes(), nil
}
func New(c Config) *Service {
	return &Service{Config: c, Run: Execute, InstanceID: "", SiteResolver: resolveProductionSite, SiteLister: listProductionSites}
}
func (s *Service) crowdsec() error {
	if !s.Config.Enabled || !s.Config.CrowdSecEnabled {
		return ErrDisabled
	}
	return nil
}
func (s *Service) List(ctx context.Context, kind string) (json.RawMessage, error) {
	if err := s.crowdsec(); err != nil {
		return nil, err
	}
	if kind != "decisions" && kind != "scenarios" {
		return nil, ErrInvalid
	}
	args := []string{kind, "list", "-o", "json"}
	if kind == "decisions" {
		args = append(args, "--limit", "100", "--no-simu")
	}
	out, err := s.Run(ctx, s.Config.CSCLIPath, args...)
	if err != nil {
		return nil, err
	}
	if !json.Valid(out) {
		return nil, errors.New("CrowdSec returned invalid JSON")
	}
	return out, nil
}

type Decision struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
}

func (s *Service) AddDecision(ctx context.Context, d Decision) error {
	if err := s.crowdsec(); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(d.IP)
	if err != nil || ip.Zone() != "" {
		return ErrInvalid
	}
	duration, err := time.ParseDuration(d.Duration)
	if err != nil || duration < time.Minute || duration > 720*time.Hour {
		return ErrInvalid
	}
	if len(d.Reason) < 1 || len(d.Reason) > 200 || strings.ContainsAny(d.Reason, "\r\n\x00") {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.Run(ctx, s.Config.CSCLIPath, "decisions", "add", "--ip", ip.String(), "--duration", d.Duration, "--reason", d.Reason, "--type", "ban")
	return err
}
func (s *Service) DeleteDecision(ctx context.Context, id string) error {
	if err := s.crowdsec(); err != nil {
		return err
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.Run(ctx, s.Config.CSCLIPath, "decisions", "delete", "--id", strconv.FormatUint(n, 10))
	return err
}

var scenarioName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

func (s *Service) Scenario(ctx context.Context, name, action string) error {
	if err := s.crowdsec(); err != nil {
		return err
	}
	if !scenarioName.MatchString(name) || (action != "install" && action != "remove") {
		return ErrInvalid
	}
	if !filepath.IsAbs(s.Config.CrowdSecReloadPath) {
		return fmt.Errorf("scenario changes disabled: configure a CrowdSec engine reload executable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.Run(ctx, s.Config.CSCLIPath, "scenarios", action, name); err != nil {
		return err
	}
	if _, err := s.Run(ctx, s.Config.CrowdSecReloadPath); err != nil {
		return errors.New("scenario files changed, but CrowdSec reload failed; reconcile engine before retrying")
	}
	return nil
}
