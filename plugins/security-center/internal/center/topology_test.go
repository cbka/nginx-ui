package security_center

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTopologyIsolatesForeignHooksAndChecksInheritedContexts(t *testing.T) {
	for _, tc := range []struct {
		name, rootHook, targetHook, foreignHook, includeAt string
		reject                                             bool
	}{
		{name: "foreign server Lua allowed", foreignHook: "access_by_lua_file /auth.lua;"},
		{name: "foreign location Lua allowed", foreignHook: "location / { access_by_lua_file /auth.lua; }"},
		{name: "target server Lua rejected", targetHook: "access_by_lua_file /auth.lua;", reject: true},
		{name: "target location Lua rejected", targetHook: "location / { access_by_lua_file /auth.lua; }", reject: true},
		{name: "inherited http Lua rejected", rootHook: "access_by_lua_file /auth.lua;", reject: true},
		{name: "inherited http ModSecurity rejected", rootHook: "modsecurity_rules_file /global.conf;", reject: true},
		{name: "server-generated inherited transaction reference allowed", rootHook: "modsecurity_transaction_id $request_id;"},
		{name: "quoted server-generated inherited transaction reference allowed", rootHook: "modsecurity_transaction_id '$request_id';"},
		{name: "double quoted server-generated reference allowed", rootHook: "modsecurity_transaction_id \"$request_id\";"},
		{name: "server-generated target reference allowed", targetHook: "modsecurity_transaction_id $request_id;"},
		{name: "client-controlled inherited reference rejected", rootHook: "modsecurity_transaction_id $http_x_request_id;", reject: true},
		{name: "custom inherited reference rejected", rootHook: "modsecurity_transaction_id prefix-$request_id;", reject: true},
		{name: "literal inherited reference rejected", rootHook: "modsecurity_transaction_id fixed;", reject: true},
		{name: "multiple reference arguments rejected", rootHook: "modsecurity_transaction_id $request_id other;", reject: true},
		{name: "reference with block rejected", rootHook: "modsecurity_transaction_id $request_id {}", reject: true},
		{name: "reference does not hide inherited inspection", rootHook: "modsecurity_transaction_id $request_id; modsecurity on;", reject: true},
		{name: "reference does not hide target access hook", rootHook: "modsecurity_transaction_id $request_id;", targetHook: "access_by_lua_file /auth.lua;", reject: true},
		{name: "included http hook rejected", includeAt: "http", reject: true},
		{name: "included target server hook rejected", includeAt: "target", reject: true},
		{name: "included target location hook rejected", includeAt: "location", reject: true},
		{name: "included foreign hook allowed", includeAt: "foreign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := siteService(t)
			target, _ := s.sitePath("a.conf")
			foreign, _ := s.sitePath("b.conf")
			inc := filepath.Join(filepath.Dir(target), "auth.conf")
			hook := fmt.Sprintf("include %s;", inc)
			switch tc.includeAt {
			case "http":
				tc.rootHook = hook
			case "target":
				tc.targetHook = hook
			case "location":
				tc.targetHook = "location / { " + hook + " }"
			case "foreign":
				tc.foreignHook = hook
			}
			root := fmt.Sprintf("http { %s include %s; include %s; }", tc.rootHook, target, foreign)
			targetBody := "server { " + tc.targetHook + " }"
			foreignBody := "server { " + tc.foreignHook + " }"
			os.WriteFile(target, []byte(targetBody), 0644)
			os.WriteFile(foreign, []byte(foreignBody), 0644)
			dump := fmt.Sprintf("# configuration file /etc/nginx/nginx.conf:\n%s\n# configuration file %s:\n%s\n# configuration file %s:\n%s\n", root, target, targetBody, foreign, foreignBody)
			if tc.includeAt != "" {
				dump += fmt.Sprintf("# configuration file %s:\naccess_by_lua_file /auth.lua;\n", inc)
			}
			err := s.checkTopology([]byte(dump), "a.conf")
			if (err != nil) != tc.reject {
				t.Fatalf("reject=%v, err=%v", tc.reject, err)
			}
		})
	}
}

func TestTopologyRechecksSharedIncludeInEachContext(t *testing.T) {
	s := siteService(t)
	target, _ := s.sitePath("a.conf")
	foreign, _ := s.sitePath("b.conf")
	inc := filepath.Join(filepath.Dir(target), "shared.conf")
	dump := fmt.Sprintf("# configuration file /etc/nginx/nginx.conf:\nhttp { include %s; include %s; }\n# configuration file %s:\nserver { include %s; }\n# configuration file %s:\nserver { location / { include %s; } }\n# configuration file %s:\naccess_by_lua_file /auth.lua;\n", foreign, target, foreign, inc, target, inc, inc)
	if s.checkTopology([]byte(dump), "a.conf") == nil {
		t.Fatal("shared hook inherited by target was allowed")
	}
}

func TestTopologyUnknownAndCyclicIncludesFailClosed(t *testing.T) {
	for _, body := range []string{"http { include missing.conf; }", "include /etc/nginx/nginx.conf;", "http { include $unsafe; }"} {
		s := siteService(t)
		if s.checkTopology([]byte("# configuration file /etc/nginx/nginx.conf:\n"+body+"\n"), "a.conf") == nil {
			t.Fatal("unresolved topology allowed")
		}
	}
}

func TestTopologyGlobAndSymlinkResolveTargetIdentity(t *testing.T) {
	s := siteService(t)
	target, _ := s.sitePath("a.conf")
	enabled := t.TempDir()
	link := filepath.Join(enabled, "target.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("# configuration file /etc/nginx/nginx.conf:\nhttp { include %s/*.conf; }\n# configuration file %s:\nserver { location / { access_by_lua_file /auth.lua; } }\n", enabled, link)
	if s.checkTopology([]byte(dump), "a.conf") == nil {
		t.Fatal("symlink target's Lua hook ignored")
	}
}

func TestTopologyMissingWildcardContentIsNotAssumedEmpty(t *testing.T) {
	s := siteService(t)
	target, _ := s.sitePath("a.conf")
	incdir := t.TempDir()
	os.WriteFile(filepath.Join(incdir, "hidden.conf"), []byte("access_by_lua_file /auth.lua;"), 0644)
	os.WriteFile(target, []byte(fmt.Sprintf("server { include %s/*.conf; }", incdir)), 0644)
	if s.checkTopology([]byte("# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"), "a.conf") == nil {
		t.Fatal("unresolved wildcard silently skipped")
	}
}

func TestForeignLuaSurvivesManagedSiteLifecycle(t *testing.T) {
	s := siteService(t)
	foreign, _ := s.sitePath("b.conf")
	original := []byte("server { listen 80; server_name legacy; location / { access_by_lua_file /auth.lua; } }\n")
	if err := os.WriteFile(foreign, original, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySite(context.Background(), "a.conf", inheritedPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := s.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(foreign)
	if err != nil || string(after) != string(original) {
		t.Fatal("unrelated Lua configuration changed")
	}
	if _, err := s.ApplySite(context.Background(), "b.conf", inheritedPolicy()); err == nil {
		t.Fatal("foreign Lua site adopted without manual integration")
	}
}
