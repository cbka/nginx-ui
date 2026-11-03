package security_center

import (
	"context"
	"encoding/json"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventQueryQuotesUntrustedHost(t *testing.T) {
	host := `x" | line_format "leak`
	q, err := eventQuery("modsecurity", host)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `vhost="x\" | line_format \"leak"`) {
		t.Fatalf("unescaped query: %s", q)
	}
	if _, err = eventQuery("x", ""); err == nil {
		t.Fatal("invalid source accepted")
	}
	if _, err = eventQuery("modsecurity", "x\ny"); err == nil {
		t.Fatal("control character accepted")
	}
}
func TestEventsProjectionAndTrustedNode(t *testing.T) {
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" || r.URL.Query().Get("limit") != "10" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		line := `{"source":"modsecurity","vhost":"example.test","node":"forged","rule_id":941100,"path":"/login?password=hidden#frag","request_body":"SECRET"}`
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{"node": "peer-1"}, "values": [][]string{{"1730000000000000000", line}}}}}})
	}))
	defer handler.Close()
	t.Setenv("SECURITY_CENTER_LOKI_URL", handler.URL)
	s := New(Config{Enabled: true})
	got, err := s.Events(context.Background(), "modsecurity", "example.test", "1h", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Node != "peer-1" || got.Items[0].Path != "/login" || got.ClusterCompletenessVerified {
		t.Fatalf("unexpected projection %+v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "hidden") {
		t.Fatal("sensitive data returned")
	}
}
func TestEventsDoNotFollowRedirect(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	t.Setenv("SECURITY_CENTER_LOKI_URL", redirect.URL)
	s := New(Config{Enabled: true})
	if _, err := s.Events(context.Background(), "crowdsec", "", "1h", 10); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 0 {
		t.Fatal("redirect followed")
	}
}
func TestEventsRejectUnboundedQuery(t *testing.T) {
	s := New(Config{Enabled: true})
	for _, tc := range []struct {
		since string
		limit int
	}{{"30d", 100}, {"1h", 0}, {"1h", 201}} {
		if _, err := s.Events(context.Background(), "crowdsec", "", tc.since, tc.limit); err != ErrInvalid {
			t.Fatalf("expected invalid: %v", err)
		}
	}
}

func TestEventsSortAcrossNodesAndRejectWrongVhost(t *testing.T) {
	makeRow := func(ts, vhost string) []string {
		data, _ := json.Marshal(SecurityEvent{Source: "modsecurity", VHost: vhost, Message: "rule match"})
		return []string{ts, string(data)}
	}
	body, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{
		map[string]any{"stream": map[string]string{"node": "one"}, "values": [][]string{makeRow("1730000000000000000", "site.conf")}},
		map[string]any{"stream": map[string]string{"node": "two"}, "values": [][]string{makeRow("1730000001000000000", "site.conf"), makeRow("1730000002000000000", "other.conf")}},
	}}})
	got, err := decodeEvents(body, "modsecurity", "site.conf", EventPage{Items: []SecurityEvent{}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 || got.Items[0].Node != "two" || got.Items[1].Node != "one" {
		t.Fatalf("wrong order/isolation: %+v", got)
	}
	limited, err := decodeEvents(body, "modsecurity", "site.conf", EventPage{Items: []SecurityEvent{}, Limit: 1})
	if err != nil || len(limited.Items) != 1 || limited.Items[0].Node != "two" {
		t.Fatalf("limit must retain newest event across streams: %+v, %v", limited, err)
	}
}

func TestEventNodeFilterIsAQuotedCollectorLabel(t *testing.T) {
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, `node="kub1"`) {
			t.Errorf("node filter absent: %s", query)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer handler.Close()
	t.Setenv("SECURITY_CENTER_LOKI_URL", handler.URL)
	s := New(Config{Enabled: true})
	if _, err := s.Events(context.Background(), "modsecurity", "", "1h", 10, "kub1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Events(context.Background(), "modsecurity", "", "1h", 10, "kub1\n"); err != ErrInvalid {
		t.Fatalf("control accepted: %v", err)
	}
}
