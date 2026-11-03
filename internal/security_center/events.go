package security_center

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SecurityEvent struct {
	Timestamp     string `json:"timestamp"`
	Source        string `json:"source"`
	VHost         string `json:"vhost"`
	Node          string `json:"node"`
	Pod           string `json:"pod,omitempty"`
	EventID       string `json:"event_id"`
	RuleID        int    `json:"rule_id,omitempty"`
	Scenario      string `json:"scenario,omitempty"`
	Message       string `json:"message"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	Parameter     string `json:"parameter,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	Action        string `json:"action,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
}
type EventPage struct {
	Items   []SecurityEvent `json:"items"`
	Limited bool            `json:"limited"`
	Limit   int             `json:"limit"`
	Since   string          `json:"since"`
	// A successful query cannot prove that every peer is shipping logs.
	ClusterCompletenessVerified bool `json:"cluster_completeness_verified"`
}

func eventQuery(source, vhost string) (string, error) {
	if source != "modsecurity" && source != "crowdsec" {
		return "", ErrInvalid
	}
	if len(vhost) > 253 || strings.ContainsAny(vhost, "\r\n\x00") {
		return "", ErrInvalid
	}
	q := `{job="nginx-security"} | json | source=` + strconv.Quote(source)
	if vhost != "" {
		q += ` | vhost=` + strconv.Quote(vhost)
	}
	return q, nil
}

// Events only queries a server-configured Loki instance and returns a normalized,
// bounded projection. Raw audit bodies, headers, query strings and credentials
// must never be included by the collector or returned through this endpoint.
func (s *Service) Events(ctx context.Context, source, vhost, since string, limit int, nodes ...string) (EventPage, error) {
	result := EventPage{Items: []SecurityEvent{}, Limited: true, Limit: limit, Since: since}
	if !s.Config.Enabled {
		return result, ErrDisabled
	}
	if limit < 1 || limit > 200 {
		return result, ErrInvalid
	}
	duration := map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour}[since]
	if duration == 0 {
		return result, ErrInvalid
	}
	query, err := eventQuery(source, vhost)
	if err != nil {
		return result, err
	}
	if len(nodes) > 1 {
		return result, ErrInvalid
	}
	if len(nodes) == 1 && nodes[0] != "" {
		node := nodes[0]
		if len(node) > 253 || strings.ContainsAny(node, "\r\n\x00") {
			return result, ErrInvalid
		}
		query = strings.Replace(query, `{job="nginx-security"}`, `{job="nginx-security",node=`+strconv.Quote(node)+`}`, 1)
	}
	endpoint := os.Getenv("NGINX_UI_SECURITY_CENTER_LOKI_URL")
	if endpoint == "" {
		return result, fmt.Errorf("central security logs are not configured: %w", ErrDisabled)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return result, errors.New("invalid server-side Loki endpoint")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/loki/api/v1/query_range"
	now := time.Now()
	q := u.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(now.Add(-duration).UnixNano(), 10))
	q.Set("end", strconv.FormatInt(now.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "backward")
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, err
	}
	if tokenFile := os.Getenv("NGINX_UI_SECURITY_CENTER_LOKI_TOKEN_FILE"); tokenFile != "" {
		info, err := os.Lstat(tokenFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
			return result, errors.New("cannot read Loki credential")
		}
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return result, errors.New("cannot read Loki credential")
		}
		token := strings.TrimSpace(string(b))
		if strings.ContainsAny(token, "\r\n") {
			return result, ErrInvalid
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return result, errors.New("central security log query failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("central security log query returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return result, errors.New("central security log response exceeds limit")
	}
	return decodeEvents(b, source, vhost, result)
}
func decodeEvents(b []byte, source, vhost string, result EventPage) (EventPage, error) {
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil || envelope.Status != "success" || envelope.Data.ResultType != "streams" {
		return result, errors.New("invalid central security log response")
	}
	for _, stream := range envelope.Data.Result {
		for _, row := range stream.Values {
			if len(row) != 2 {
				continue
			}
			n, err := strconv.ParseInt(row[0], 10, 64)
			if err != nil {
				continue
			}
			var event SecurityEvent
			if json.Unmarshal([]byte(row[1]), &event) != nil || event.Source != source || (vhost != "" && event.VHost != vhost) {
				continue
			}
			event.Timestamp = time.Unix(0, n).UTC().Format(time.RFC3339Nano)
			// Node identity comes from collector labels, never request-controlled fields.
			event.Node = stream.Stream["node"]
			event.Pod = stream.Stream["pod"]
			event.Path = strings.SplitN(strings.SplitN(event.Path, "?", 2)[0], "#", 2)[0]
			fields := []*string{&event.VHost, &event.Node, &event.Pod, &event.EventID, &event.Scenario, &event.Message, &event.Method, &event.Path, &event.Parameter, &event.ClientIP, &event.Action, &event.TransactionID}
			for _, field := range fields {
				if len(*field) > 512 {
					*field = (*field)[:512]
				}
			}
			result.Items = append(result.Items, event)
		}
	}
	sort.SliceStable(result.Items, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, result.Items[i].Timestamp)
		b, _ := time.Parse(time.RFC3339Nano, result.Items[j].Timestamp)
		return a.After(b)
	})
	if len(result.Items) > result.Limit {
		result.Items = result.Items[:result.Limit]
	}
	return result, nil
}
