package clustersync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0xJacky/Nginx-UI/model"
	"github.com/go-resty/resty/v2"
)

func TestSiteDeploymentStatePreservesMaintenance(t *testing.T) {
	conf := withConfDir(t, map[string]string{
		"sites-enabled/normal":                           "server {}",
		"sites-enabled/maintenance_nginx_ui_maintenance": "server {}",
		"sites-enabled/conflicting":                      "server {}",
		"sites-enabled/conflicting_nginx_ui_maintenance": "server {}",
	})
	for _, tc := range []struct {
		name  string
		state siteState
	}{
		{"normal", siteStateEnabled}, {"maintenance", siteStateMaintenance},
		{"conflicting", siteStateMaintenance}, {"disabled", siteStateDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := siteDeploymentState(&model.Site{Path: filepath.Join(conf, "sites-available", tc.name)})
			if got != tc.state {
				t.Fatalf("state %q, want %q", got, tc.state)
			}
		})
	}
	remote := &model.Site{Path: filepath.Join(conf, "sites-available", "remote"), Namespace: &model.Namespace{DeployMode: model.DeployModeRemote}, RemoteEnabled: true}
	if siteDeploymentState(remote) != siteStateEnabled {
		t.Fatal("remote enabled intent changed")
	}
	remote.RemoteEnabled = false
	if siteDeploymentState(remote) != siteStateDisabled {
		t.Fatal("remote disabled intent changed")
	}
}

func TestMaintenanceSyncNeverEnablesOrDisables(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if r.URL.Path == "/api/sites/example/maintenance" {
					w.WriteHeader(code)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			node := nodeRef{client: resty.New().SetBaseURL(srv.URL)}
			err := siteStateItem("example", "server {}", "", "none", siteStateMaintenance, true).push(context.Background(), node)
			if (err == nil) != (code == http.StatusOK) {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(paths, []string{"/api/sites/example", "/api/sites/example/maintenance"}) {
				t.Fatalf("unsafe state transition: %v", paths)
			}
		})
	}
}

func TestSiteSyncOrdinaryStatesUnchanged(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		var paths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		node := nodeRef{client: resty.New().SetBaseURL(srv.URL)}
		err := siteItem("example", "server {}", "", "none", enabled, true).push(context.Background(), node)
		srv.Close()
		endpoint := "/disable"
		if enabled {
			endpoint = "/enable"
		}
		if err != nil || !reflect.DeepEqual(paths, []string{"/api/sites/example", "/api/sites/example" + endpoint}) {
			t.Fatalf("ordinary behavior changed: %v %v", paths, err)
		}
	}
}

func TestCollectSiteItemsSkipsGeneratedMaintenanceArtifacts(t *testing.T) {
	db := withSiteDB(t)
	conf := withConfDir(t, map[string]string{
		"sites-available/example":                      "server {}",
		"sites-available/example_nginx_ui_maintenance": "server {}",
		"sites-enabled/example_nginx_ui_maintenance":   "server {}",
	})
	for _, name := range []string{"example", "example_nginx_ui_maintenance"} {
		if err := db.Create(&model.Site{Path: filepath.Join(conf, "sites-available", name)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	items, files, err := collectSiteItems(nil, true)
	if err != nil || len(items) != 1 || len(files) != 1 || items[0].name != "example" {
		t.Fatalf("generated guard treated as an independent site: %d %d %v", len(items), len(files), err)
	}
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := items[0].push(context.Background(), nodeRef{client: resty.New().SetBaseURL(srv.URL)}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{"/api/sites/example", "/api/sites/example/maintenance"}) {
		t.Fatalf("collector lost maintenance state: %v", paths)
	}
}
