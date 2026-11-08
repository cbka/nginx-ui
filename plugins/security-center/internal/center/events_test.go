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

func TestEventsPreserveCollectorSourceIP(t *testing.T) {
	for _, source := range []string{"modsecurity", "crowdsec"} {
		for _, address := range []string{"192.0.2.8", "2001:db8::8", ""} {
			t.Run(source+"/"+address, func(t *testing.T) {
				line, _ := json.Marshal(map[string]string{"source": source, "client_ip": address, "x_forwarded_for": "203.0.113.99"})
				body, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{
					map[string]any{"stream": map[string]string{"node": "kub1", "pod": "peer-0", "client_ip": "203.0.113.88"}, "values": [][]string{{"1730000000000000000", string(line)}}},
				}}})
				got, err := decodeEvents(body, source, "", EventPage{Items: []SecurityEvent{}, Limit: 10})
				if err != nil || len(got.Items) != 1 {
					t.Fatalf("unexpected response: %+v, %v", got, err)
				}
				if got.Items[0].ClientIP != address {
					t.Fatalf("source IP lost or replaced: %q", got.Items[0].ClientIP)
				}
				encoded, _ := json.Marshal(got.Items[0])
				if strings.Contains(string(encoded), "203.0.113.") {
					t.Fatal("untrusted IP field leaked into event")
				}
			})
		}
	}
}

func TestEventsRequestReferenceFilterBeforeLimit(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, `transaction_id="`+id+`"`) || r.URL.Query().Get("limit") != "10" {
			t.Errorf("exact reference must be queried in Loki before limiting: %s", r.URL.RawQuery)
		}
		if !strings.Contains(query, `node="kub1"`) || !strings.Contains(query, `source=~"modsecurity|crowdsec"`) {
			t.Errorf("source/node filters missing: %s", query)
		}
		rows := [][]string{}
		for _, source := range []string{"modsecurity", "crowdsec", "untrusted"} {
			line, _ := json.Marshal(SecurityEvent{Source: source, TransactionID: id})
			rows = append(rows, []string{"1730000000000000000", string(line)})
		}
		other, _ := json.Marshal(SecurityEvent{Source: "crowdsec", TransactionID: "different"})
		rows = append(rows, []string{"1730000000000000000", string(other)})
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{"node": "kub1"}, "values": rows}}}})
	}))
	defer handler.Close()
	t.Setenv("SECURITY_CENTER_LOKI_URL", handler.URL)
	s := New(Config{Enabled: true})
	got, err := s.EventsForRequest(context.Background(), "all", "", "1h", 10, "kub1", id)
	if err != nil || len(got.Items) != 2 {
		t.Fatalf("matching events across both sources only: %+v %v", got, err)
	}
	for _, item := range got.Items {
		if item.TransactionID != id {
			t.Fatal("wrong reference returned")
		}
	}
}

func TestEventsRejectInvalidRequestReference(t *testing.T) {
	s := New(Config{Enabled: true})
	for _, id := range []string{"x\ny", `x" | json`, strings.Repeat("a", 129), "<script>", "white space"} {
		if _, err := s.EventsForRequest(context.Background(), "all", "", "1h", 10, "", id); err != ErrInvalid {
			t.Errorf("invalid reference %q accepted: %v", id, err)
		}
	}
	// Legacy transaction IDs may contain punctuation, but never query syntax.
	for _, id := range []string{"", "legacy-id_1.2:3", strings.Repeat("a", 32)} {
		if _, err := requestReferenceQuery(id); err != nil {
			t.Errorf("valid reference rejected: %q", id)
		}
	}
}
