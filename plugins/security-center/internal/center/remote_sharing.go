package security_center

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) remoteControlConfigured() bool {
	return s.Config.ControlURL != "" || s.Config.ControlTokenFile != ""
}

// The remote controller is operator-configured; browser requests supply only a
// boolean. Projected Kubernetes secret symlinks are permitted for the token file,
// but the opened target must be a small regular file at an absolute path.
func (s *Service) remoteSharing(ctx context.Context, enabled *bool) (SharingStatus, error) {
	var result SharingStatus
	invalid := errors.New("central CrowdSec control configuration is invalid")
	endpoint, err := url.Parse(s.Config.ControlURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || !filepath.IsAbs(s.Config.ControlTokenFile) {
		return result, invalid
	}
	f, err := os.Open(s.Config.ControlTokenFile)
	if err != nil {
		return result, invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return result, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return result, invalid
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return result, invalid
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return result, invalid
		}
	}
	endpoint.Path = "/sharing"
	endpoint.RawPath = ""
	method := http.MethodGet
	var body io.Reader
	if enabled != nil {
		method = http.MethodPut
		b, _ := json.Marshal(map[string]bool{"enabled": *enabled})
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return result, invalid
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if enabled != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// No environment proxy: control traffic and its bearer token stay on the
	// configured direct endpoint. Redirects must never forward credentials.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("central CrowdSec control request failed; state unknown")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("central CrowdSec control rejected the request; state unknown")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(b) > 65536 {
		return result, errors.New("central CrowdSec control response exceeds limit or is unreadable")
	}
	var wire struct {
		Configured      *bool           `json:"configured"`
		Enabled         json.RawMessage `json:"enabled"`
		RuntimeVerified *bool           `json:"runtime_verified"`
		Editable        *bool           `json:"editable"`
		Message         string          `json:"message"`
	}
	if json.Unmarshal(b, &wire) != nil || wire.Configured == nil || wire.RuntimeVerified == nil || wire.Editable == nil || len(wire.Enabled) == 0 || len(wire.Message) > 2048 {
		return result, errors.New("central CrowdSec control returned invalid status")
	}
	if json.Unmarshal(wire.Enabled, &result.Enabled) != nil {
		return result, errors.New("central CrowdSec control returned invalid sharing value")
	}
	result.Configured = *wire.Configured
	result.Editable = *wire.Editable
	result.RuntimeVerified = *wire.RuntimeVerified
	// Do not expose arbitrary remote diagnostics (which could contain secrets).
	result.Message = "Central engine sharing configuration; enforcement and community delivery are separate."
	if !result.Configured {
		result.Enabled = nil
		result.Editable = false
		result.RuntimeVerified = false
	}
	if enabled != nil && (!result.Configured || result.Enabled == nil || *result.Enabled != *enabled) {
		return SharingStatus{}, errors.New("central CrowdSec control did not confirm the requested sharing value")
	}
	return result, nil
}
