package security_center

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type ReplicaPayload struct {
	Name     string     `json:"name"`
	Owner    string     `json:"owner"`
	Revision int64      `json:"revision,string"`
	Policy   SitePolicy `json:"policy"`
	Global   WAFConfig  `json:"global"`
}

func nextRevision(previous int64) int64 {
	now := time.Now().UnixNano()
	if now <= previous {
		return previous + 1
	}
	return now
}
func (p ReplicaPayload) hash() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Service) ExportSite(name string) (ReplicaPayload, error) {
	if err := s.waf(); err != nil {
		return ReplicaPayload{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	if _, err := s.sitePath(name); err != nil {
		return ReplicaPayload{}, err
	}
	state, err := s.readPolicy(name)
	if err != nil {
		return ReplicaPayload{}, err
	}
	if state.Replica || state.Revision <= 0 || state.Owner != s.InstanceID || s.InstanceID == "" {
		return ReplicaPayload{}, errors.New("only a locally managed saved policy can be synchronized")
	}
	global, err := s.readWAF()
	if err != nil {
		return ReplicaPayload{}, err
	}
	return ReplicaPayload{Name: name, Owner: state.Owner, Revision: state.Revision, Policy: state.Policy, Global: global}, nil
}

// ApplyReplica is called only after verifying a paired controller signature.
// Its global snapshot is stored on this site, never in the receiver's defaults.
func (s *Service) ApplyReplica(ctx context.Context, p ReplicaPayload, controller string) (bool, error) {
	if err := s.waf(); err != nil {
		return false, err
	}
	if controller == "" || p.Owner != controller || p.Revision <= 0 {
		return false, ErrInvalid
	}
	if err := p.Global.Validate(); err != nil {
		return false, err
	}
	if _, err := effectivePolicy(p.Global, p.Policy); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expected = nil
	if _, err := s.sitePath(p.Name); err != nil {
		return false, err
	}
	old, err := s.readPolicy(p.Name)
	if err != nil {
		return false, err
	}
	hash := p.hash()
	if old.Revision > 0 {
		if !old.Replica || old.Owner != controller {
			return false, errors.New("site policy is already owned by another controller or locally managed")
		}
		if p.Revision < old.Revision {
			return false, errors.New("stale site policy revision rejected")
		}
		if p.Revision == old.Revision && hash != old.ContentHash {
			return false, errors.New("conflicting payload for existing revision rejected")
		}
	}
	if err = s.prepareSiteDir(); err != nil {
		return false, err
	}
	state := SiteState{Name: p.Name, Owner: p.Owner, Revision: p.Revision, Policy: p.Policy, Replica: true, GlobalSnapshot: &p.Global, ContentHash: hash}
	changes, err := s.stateChanges(p.Global, state)
	if err != nil {
		return false, err
	}
	if old.Revision == p.Revision && old.ContentHash == hash {
		same := true
		for _, change := range changes {
			b, err := os.ReadFile(change.path)
			if err != nil || !bytes.Equal(b, change.data) {
				same = false
				break
			}
		}
		if same {
			return false, nil
		}
	}
	dump, err := s.Run(ctx, s.Config.NginxPath, "-T")
	if err != nil {
		return false, err
	}
	if err = s.checkTopology(dump, p.Name); err != nil {
		return false, err
	}
	if err = s.applyFiles(ctx, changes); err != nil {
		return false, err
	}
	return true, nil
}
