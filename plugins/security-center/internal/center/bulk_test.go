package security_center

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestBulkRejectsBeforeCommand(t *testing.T) {
	s := New(Config{Enabled: true, CrowdSecEnabled: true, AppSecEnabled: true, CrowdSecReloadPath: "/reload"})
	calls := 0
	s.Run = func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte(`{}`), nil }
	if _, e := s.BulkPreview(context.Background(), "../x"); e == nil {
		t.Fatal("invalid kind accepted")
	}
	if _, e := s.BulkStart(context.Background(), "appsec", "bad"); e == nil {
		t.Fatal("invalid token accepted")
	}
	if _, e := s.BulkStatus(context.Background(), "../job"); e == nil {
		t.Fatal("invalid job accepted")
	}
	s.Config.Enabled = false
	if _, e := s.BulkPreview(context.Background(), "scenarios"); e == nil {
		t.Fatal("disabled plugin accepted")
	}
	if calls != 0 {
		t.Fatal("invalid input ran command")
	}
}
func TestBulkUsesBoundedCentralBridge(t *testing.T) {
	s := New(Config{Enabled: true, CrowdSecEnabled: true, AppSecEnabled: true, CrowdSecReloadPath: "/reload"})
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"bulk", "start", "appsec", strings.Repeat("a", 64)}) {
			t.Fatal(args)
		}
		return []byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"queued"}`), nil
	}
	if _, e := s.BulkStart(context.Background(), "appsec", strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"operation_error":"Katalog geändert; Vorschau neu laden"}`), nil
	}
	if _, e := s.BulkStart(context.Background(), "appsec", strings.Repeat("a", 64)); e == nil {
		t.Fatal("rejection hidden")
	}
}

func TestDeactivateWaitsForBulkRollbackBeforeSiteChanges(t *testing.T) {
	s := siteService(t)
	ctx := context.Background()
	if _, err := s.ApplySite(ctx, "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	original := s.Run
	calls := 0
	s.Run = func(c context.Context, p string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "bulk" {
			calls++
			if calls == 1 {
				return []byte(`{"state":"running"}`), nil
			}
			return []byte(`{"state":"failed","recovery_required":false}`), nil
		}
		if calls < 2 {
			t.Fatal("Nginx changed before bulk completion")
		}
		return original(c, p, args...)
	}
	if err := s.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestDeactivateRejectsUnrecoveredBulk(t *testing.T) {
	s := siteService(t)
	s.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"state":"failed","recovery_required":true}`), nil
	}
	if s.Deactivate(context.Background()) == nil {
		t.Fatal("unsafe disable accepted")
	}
}

func TestBulkLifecycleAdmission(t *testing.T) {
	s := siteService(t)
	s.Config.CrowdSecReloadPath = "/reload"
	ctx := context.Background()
	starts := 0
	unsafe := false
	s.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[0] == "bulk" && args[1] == "start" {
			starts++
			return []byte(`{"state":"queued"}`), nil
		}
		if unsafe {
			return []byte(`{"state":"failed","recovery_required":true}`), nil
		}
		return []byte(`null`), nil
	}
	if err := s.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BulkStart(ctx, "scenarios", strings.Repeat("a", 64)); err == nil {
		t.Fatal("start admitted after disable")
	}
	if starts != 0 {
		t.Fatal("disabled start invoked bridge")
	}
	if err := s.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BulkStart(ctx, "scenarios", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	unsafe = true
	if err := s.Deactivate(ctx); err == nil {
		t.Fatal("unsafe deactivation succeeded")
	}
	if _, err := s.BulkStart(ctx, "scenarios", strings.Repeat("a", 64)); err != nil {
		t.Fatal("failed lifecycle left local admission blocked", err)
	}
	if starts != 2 {
		t.Fatal(starts)
	}
}
