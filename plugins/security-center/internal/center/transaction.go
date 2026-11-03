package security_center

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// Change is submitted to the host's globally serialized, validated transaction.
type Change struct {
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Delete         bool   `json:"delete,omitempty"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (s *Service) remember(path string, b []byte, missing bool) {
	if s.expected == nil {
		s.expected = map[string]string{}
	}
	if _, ok := s.expected[path]; ok {
		return
	}
	if missing {
		s.expected[path] = "missing"
	} else {
		s.expected[path] = digest(b)
	}
}
func (s *Service) commit(ctx context.Context, changes []fileChange) error {
	defer func() { s.expected = nil }()
	out := make([]Change, 0, len(changes))
	for _, c := range changes {
		if err := safeFile(c.path); err != nil {
			return err
		}
		if _, ok := s.expected[c.path]; !ok {
			b, err := os.ReadFile(c.path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			s.remember(c.path, b, os.IsNotExist(err))
		}
		out = append(out, Change{Path: c.path, Content: string(c.data), ExpectedSHA256: s.expected[c.path]})
	}
	return s.Transaction(ctx, out)
}
