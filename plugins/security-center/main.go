// Security Center is a resident native plugin. Only transport types come from
// the host module; security policies, APIs and persistence belong to this binary.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xJacky/Nginx-UI/internal/plugin/jsonrpc"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	api "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/api"
	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const pluginID = "io.github.mctdatapool.security-center"

type application struct {
	mu              sync.RWMutex
	service         *center.Service
	ready           bool
	failure         string
	conn            *jsonrpc.Conn
	initializedDone chan struct{}
}

// The host starts this process only for an enabled plugin. Engine availability
// remains an independent operator configuration; plugin activation grants no
// new WAF or CrowdSec enforcement by itself.
func activePluginConfig() center.Config {
	c := center.EnvironmentConfig()
	c.Enabled = true
	return c
}

func (a *application) start(ctx context.Context) error {
	var info struct {
		InstanceID    string `json:"instance_id"`
		NginxConfDir  string `json:"nginx_conf_dir"`
		PersistentDir string `json:"persistent_dir"`
	}
	if err := a.conn.Call(ctx, "host.runtime.info", struct{}{}, &info); err != nil {
		return err
	}
	if info.InstanceID == "" || !filepath.IsAbs(info.PersistentDir) || !filepath.IsAbs(info.NginxConfDir) {
		return errors.New("invalid host runtime information")
	}
	c := activePluginConfig()
	c.ModSecurityPath = filepath.Join(info.PersistentDir, "modsecurity.conf")
	if err := os.MkdirAll(info.PersistentDir, 0750); err != nil {
		return err
	}
	s := center.New(c)
	s.InstanceID = info.InstanceID
	s.SiteResolver = func(name string) (string, error) {
		var result struct {
			Path string `json:"path"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := a.conn.Call(ctx, "host.sites.resolve", map[string]string{"name": name}, &result)
		return result.Path, err
	}
	s.SiteLister = func() ([]string, error) {
		var result protocol.HostSitesListResult
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.conn.Call(ctx, "host.sites.list", struct{}{}, &result); err != nil {
			return nil, err
		}
		out := []string{}
		for _, site := range result.Sites {
			out = append(out, site.Name)
		}
		return out, nil
	}
	s.Transaction = func(ctx context.Context, files []center.Change) error {
		var result struct {
			Applied bool `json:"applied"`
		}
		if err := a.conn.Call(ctx, "host.nginx.transaction", map[string]any{"files": files, "reload": true}, &result); err != nil {
			return err
		}
		if !result.Applied {
			return errors.New("host did not confirm transaction")
		}
		return nil
	}
	if err := s.Migrate(ctx, filepath.Join(info.NginxConfDir, "security-center")); err != nil {
		return err
	}
	if err := s.Activate(ctx); err != nil {
		return err
	}
	a.service = s
	api.SetService(s)
	api.HostCall = a.conn.Call
	a.ready = true
	return nil
}
func (a *application) guarded(next http.Handler, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Nginx-UI-Plugin-Secret")), []byte(secret)) != 1 {
			http.Error(w, "Forbidden", 403)
			return
		}
		a.mu.RLock()
		defer a.mu.RUnlock()
		if !a.ready {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Security plugin is not ready: " + a.failure})
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *application) activate(ctx context.Context, _ json.RawMessage) (any, error) {
	select {
	case <-a.initializedDone:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.ready {
		return nil, errors.New("Security activation failed: " + a.failure)
	}
	return map[string]bool{"activated": true}, nil
}
func main() {
	conn := jsonrpc.NewConn(os.Stdin, os.Stdout)
	a := &application{conn: conn, failure: "initializing", initializedDone: make(chan struct{})}
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	api.InitRouter(router.Group(""))
	data := os.Getenv("NGINX_UI_PLUGIN_DATA_DIR")
	secret := os.Getenv("NGINX_UI_PLUGIN_HTTP_SECRET")
	if !filepath.IsAbs(data) || secret == "" {
		fmt.Fprintln(os.Stderr, "plugin launch environment missing")
		os.Exit(1)
	}
	socket := filepath.Join(data, "http.sock")
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Chmod(socket, 0600)
	server := &http.Server{Handler: a.guarded(router, secret), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	go server.Serve(listener)
	conn.Handle("plugin.initialize", func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"api_version": 1, "capabilities": []string{"http"}}, nil
	})
	conn.Handle("plugin.initialized", func(ctx context.Context, _ json.RawMessage) (any, error) {
		defer close(a.initializedDone)
		a.mu.Lock()
		defer a.mu.Unlock()
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		if err := a.start(ctx); err != nil {
			a.failure = err.Error()
			fmt.Fprintln(os.Stderr, "Security plugin startup:", err)
			return nil, err
		}
		return struct{}{}, nil
	})
	conn.Handle("plugin.activate", a.activate)
	conn.Handle("plugin.ping", func(context.Context, json.RawMessage) (any, error) {
		select {
		case <-a.initializedDone:
			a.mu.RLock()
			defer a.mu.RUnlock()
			if !a.ready {
				return nil, errors.New("Security plugin unavailable: " + a.failure)
			}
		default:
		}
		return struct{}{}, nil
	})
	conn.Handle("plugin.configure", func(context.Context, json.RawMessage) (any, error) { return struct{}{}, nil })
	conn.Handle("plugin.deactivate", func(ctx context.Context, p json.RawMessage) (any, error) {
		var v struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(p, &v) != nil || (v.Reason != "disable" && v.Reason != "uninstall") {
			return nil, center.ErrInvalid
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if !a.ready {
			return nil, errors.New("plugin cannot confirm security deactivation while unavailable")
		}
		if err := a.service.Deactivate(ctx); err != nil {
			return nil, err
		}
		a.ready = false
		a.failure = "disabled"
		return map[string]bool{"deactivated": true}, nil
	})
	conn.Handle(protocol.MethodClusterSiteApply, func(ctx context.Context, p json.RawMessage) (any, error) {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if !a.ready {
			return nil, errors.New("security plugin is unavailable")
		}
		return api.ApplyReplica(ctx, p)
	})
	conn.Handle("plugin.shutdown", func(context.Context, json.RawMessage) (any, error) { return struct{}{}, nil })
	conn.Handle("plugin.exit", func(context.Context, json.RawMessage) (any, error) { go conn.Close(); return nil, nil })
	_ = conn.Serve(context.Background())
	_ = server.Close()
}
