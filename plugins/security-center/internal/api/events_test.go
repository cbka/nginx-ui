package security_center

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
)

func TestEventsRouteForwardsExactRequestReference(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := service
	t.Cleanup(func() { service = previous })
	const id = "0123456789abcdef0123456789abcdef"
	calls := 0
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.URL.Query().Get("query"), `transaction_id="`+id+`"`) {
			t.Error("request reference not passed to Loki")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer loki.Close()
	t.Setenv("SECURITY_CENTER_LOKI_URL", loki.URL)
	SetService(center.New(center.Config{Enabled: true}))
	r := gin.New()
	r.GET("/events", Events)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/events?source=all&request_id="+id, nil))
	if w.Code != 200 || calls != 1 {
		t.Fatalf("route returned %d / %d Loki calls", w.Code, calls)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/events?source=all&request_id=bad%0Aid", nil))
	if w.Code != 400 || calls != 1 {
		t.Fatalf("invalid reference reached Loki: %d / %d calls", w.Code, calls)
	}
}
