package security_center

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"time"
)

var bulkToken = regexp.MustCompile(`^[a-f0-9]{64}$`)
var bulkID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Service) bulkAllowed(kind string) error {
	if err := s.crowdsec(); err != nil {
		return err
	}
	if kind != "scenarios" && kind != "appsec" {
		return ErrInvalid
	}
	if kind == "appsec" && !s.Config.AppSecEnabled {
		return ErrDisabled
	}
	if kind == "scenarios" && !filepath.IsAbs(s.Config.CrowdSecReloadPath) {
		return ErrDisabled
	}
	return nil
}
func (s *Service) bulkCommand(ctx context.Context, args ...string) (json.RawMessage, error) {
	out, err := s.Run(ctx, s.Config.CSCLIPath, args...)
	if err != nil {
		return nil, err
	}
	if err = operationError(out); err != nil {
		return nil, err
	}
	if !json.Valid(out) {
		return nil, ErrInvalid
	}
	return out, nil
}
func (s *Service) BulkPreview(ctx context.Context, kind string) (json.RawMessage, error) {
	if err := s.bulkAllowed(kind); err != nil {
		return nil, err
	}
	return s.bulkCommand(ctx, "bulk", "preview", kind)
}
func (s *Service) BulkStart(ctx context.Context, kind, token string) (json.RawMessage, error) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	if s.bulkDisabled {
		return nil, ErrDisabled
	}
	if err := s.bulkAllowed(kind); err != nil {
		return nil, err
	}
	if !bulkToken.MatchString(token) {
		return nil, ErrInvalid
	}
	return s.bulkCommand(ctx, "bulk", "start", kind, token)
}
func (s *Service) BulkStatus(ctx context.Context, id string) (json.RawMessage, error) {
	if err := s.crowdsec(); err != nil {
		return nil, err
	}
	if id != "current" && !bulkID.MatchString(id) {
		return nil, ErrInvalid
	}
	return s.bulkCommand(ctx, "bulk", "status", id)
}

// Deactivation never switches off the shared engine for other enabled peers.
// It only cancels a central bulk transaction and waits for its safe rollback.
func (s *Service) cancelBulkBeforeDeactivate(ctx context.Context) error {
	if !s.Config.CrowdSecEnabled || s.Config.CSCLIPath == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := s.bulkCommand(ctx, "bulk", "cancel")
	if err != nil {
		return err
	}
	for {
		var job struct {
			State            string `json:"state"`
			RecoveryRequired bool   `json:"recovery_required"`
		}
		if json.Unmarshal(out, &job) != nil {
			return ErrInvalid
		}
		if job.RecoveryRequired {
			return errors.New("bulk rollback requires manual recovery; plugin remains enabled")
		}
		if job.State != "queued" && job.State != "running" && job.State != "validating" {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("bulk cancellation still running; retry disabling after rollback")
		case <-time.After(250 * time.Millisecond):
		}
		out, err = s.bulkCommand(ctx, "bulk", "status", "current")
		if err != nil {
			return err
		}
	}
}
