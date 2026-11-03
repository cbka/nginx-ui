package security_center

import (
	"context"
	"os"
	"testing"
)

func TestReplicaOwnershipRevisionIdempotenceAndGlobalIsolation(t *testing.T) {
	source := siteService(t)
	source.InstanceID = "source"
	peer := siteService(t)
	peer.InstanceID = "peer"
	ctx := context.Background()
	local := validConfig()
	local.ParanoiaLevel = 4
	if err := peer.ApplyWAF(ctx, local); err != nil {
		t.Fatal(err)
	}
	peerDefaults, _ := os.ReadFile(peer.Config.ModSecurityPath)
	if _, err := source.ApplySite(ctx, "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	payload, err := source.ExportSite("a.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = peer.ApplyReplica(ctx, payload, "wrong-source"); err == nil {
		t.Fatal("forged owner accepted")
	}
	changed, err := peer.ApplyReplica(ctx, payload, "source")
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	meta, rules, snippet := peer.sitePaths("a.conf")
	sitePath, _ := peer.sitePath("a.conf")
	beforeFiles := map[string]string{}
	for _, path := range []string{meta, rules, snippet, sitePath} {
		b, _ := os.ReadFile(path)
		beforeFiles[path] = string(b)
	}
	again, err := peer.ApplyReplica(ctx, payload, "source")
	if err != nil || again {
		for path, before := range beforeFiles {
			after, _ := os.ReadFile(path)
			if before != string(after) {
				t.Logf("Changed %s\nBEFORE:%s\nAFTER:%s", path, before, after)
			}
		}
		t.Fatal("same revision not idempotent", again, err)
	}
	after, _ := os.ReadFile(peer.Config.ModSecurityPath)
	if string(after) != string(peerDefaults) {
		t.Fatal("peer defaults overwritten")
	}
	view, err := peer.GetSite("a.conf")
	if err != nil || view.Effective.ModSecurity.ParanoiaLevel != 1 {
		t.Fatal("source snapshot not effective", view, err)
	}
	stale := payload
	stale.Revision--
	if _, err = peer.ApplyReplica(ctx, stale, "source"); err == nil {
		t.Fatal("stale accepted")
	}
	different := payload
	different.Global.Mode = "On"
	if _, err = peer.ApplyReplica(ctx, different, "source"); err == nil {
		t.Fatal("conflicting same revision accepted")
	}
	if _, err = peer.ApplySite(ctx, "a.conf", inheritedPolicy()); err == nil {
		t.Fatal("local editing source-owned replica accepted")
	}
	if _, err = peer.ExportSite("a.conf"); err == nil {
		t.Fatal("replication loop allowed")
	}
	local.Mode = "Off"
	if err = peer.ApplyWAF(ctx, local); err != nil {
		t.Fatal(err)
	}
	view, err = peer.GetSite("a.conf")
	if err != nil || view.Effective.ModSecurity.Mode != "DetectionOnly" {
		t.Fatal("receiver global edit changed replica", view, err)
	}
}
func TestReplicaCannotReplaceLocallyOwnedPolicy(t *testing.T) {
	s := siteService(t)
	if _, err := s.ApplySite(context.Background(), "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	p := ReplicaPayload{Name: "a.conf", Owner: "other", Revision: nextRevision(0), Policy: inheritedPolicy(), Global: validConfig()}
	if _, err := s.ApplyReplica(context.Background(), p, "other"); err == nil {
		t.Fatal("overwrote locally owned policy")
	}
}
