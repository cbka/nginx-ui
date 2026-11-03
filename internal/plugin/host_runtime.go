package plugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/0xJacky/Nginx-UI/internal/plugin/jsonrpc"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/settings"
)

type RuntimeInfo struct {
	InstanceID    string `json:"instance_id"`
	NginxConfDir  string `json:"nginx_conf_dir"`
	PersistentDir string `json:"persistent_dir"`
}
type ConfigChange struct {
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Delete         bool   `json:"delete,omitempty"`
}
type ConfigTransaction struct {
	Files  []ConfigChange `json:"files"`
	Reload bool           `json:"reload"`
}
type runtimeHostBackend interface {
	RuntimeInfo(string) (RuntimeInfo, error)
	ResolveSite(string) (string, error)
	ApplyTransaction(string, ConfigTransaction) error
}

func registerRuntimeHostHandlers(conn *jsonrpc.Conn, id string, granted []string, backend HostBackend) {
	b, ok := backend.(runtimeHostBackend)
	if !ok {
		return
	}
	conn.Handle("host.runtime.info", func(ctx context.Context, p json.RawMessage) (any, error) {
		if err := requirePermission(granted, "nginx.transaction"); err != nil {
			return nil, err
		}
		return b.RuntimeInfo(id)
	})
	conn.Handle("host.sites.resolve", func(ctx context.Context, p json.RawMessage) (any, error) {
		if err := requirePermission(granted, "nginx.transaction"); err != nil {
			return nil, err
		}
		var v struct {
			Name string `json:"name"`
		}
		if err := decodeParams(p, &v); err != nil {
			return nil, err
		}
		path, err := b.ResolveSite(v.Name)
		return map[string]string{"path": path}, err
	})
	conn.Handle("host.nginx.transaction", func(ctx context.Context, p json.RawMessage) (any, error) {
		if err := requirePermission(granted, "nginx.transaction"); err != nil {
			return nil, err
		}
		if len(p) > 3<<20 {
			return nil, jsonrpc.Errorf(protocol.CodeInvalidParams, "transaction exceeds 3 MiB")
		}
		var v ConfigTransaction
		if err := decodeParams(p, &v); err != nil {
			return nil, err
		}
		if err := b.ApplyTransaction(id, v); err != nil {
			return nil, err
		}
		return map[string]bool{"applied": true}, nil
	})
}
func (b *hostBackend) RuntimeInfo(id string) (RuntimeInfo, error) {
	root := filepath.Join(b.nginxConfDir(), "plugins-persistent", id)

	return RuntimeInfo{settings.NodeSettings.InstanceID, b.nginxConfDir(), root}, nil
}
func (b *hostBackend) ResolveSite(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("invalid site name")
	}
	path, err := site.ResolveAvailablePath(name)
	if err != nil {
		return "", err
	}
	if err = site.CheckManaged(name); err != nil {
		return "", err
	}
	info, err := nginx.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("site must be a regular file")
	}
	return path, nil
}
func beneath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Reject symlinks in every component, including not-yet-created descendants.
func plainPath(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := nginx.Lstat(p)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink config paths are not permitted")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
func (b *hostBackend) ApplyTransaction(id string, tx ConfigTransaction) error {
	if !tx.Reload {
		return fmt.Errorf("transaction must validate and reload nginx")
	}
	if len(tx.Files) == 0 || len(tx.Files) > 256 {
		return fmt.Errorf("transaction needs 1 to 256 files")
	}
	info, err := b.RuntimeInfo(id)
	if err != nil {
		return err
	}
	release := config.LockApply()
	defer release()
	snapshots := make([]config.FileSnapshot, len(tx.Files))
	seen := map[string]bool{}
	total := 0
	for i, f := range tx.Files {
		if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || seen[f.Path] {
			return fmt.Errorf("invalid or duplicate transaction path")
		}
		seen[f.Path] = true
		if !beneath(info.PersistentDir, f.Path) {
			if filepath.Dir(f.Path) != filepath.Join(info.NginxConfDir, "sites-available") || f.Delete {
				return fmt.Errorf("transaction path outside allowed roots")
			}
			resolved, e := b.ResolveSite(filepath.Base(f.Path))
			if e != nil {
				return e
			}
			if resolved != f.Path {
				return fmt.Errorf("noncanonical site path")
			}
		}
		if err = plainPath(f.Path); err != nil {
			return err
		}
		total += len(f.Content)
		if len(f.Content) > 1<<20 || total > 3<<20 {
			return fmt.Errorf("transaction content limit exceeded")
		}
		current, e := readTransactionFile(f.Path)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		expected := "missing"
		if e == nil {
			sum := sha256.Sum256(current)
			expected = hex.EncodeToString(sum[:])
		}
		if f.ExpectedSHA256 != expected {
			return fmt.Errorf("configuration changed before transaction: %s", f.Path)
		}
		snapshots[i], err = config.CaptureFile(f.Path)
		if err != nil {
			return err
		}
	}
	touched := 0
	restore := func() error {
		var errs []error
		for i := touched - 1; i >= 0; i-- {
			errs = append(errs, snapshots[i].Restore(tx.Files[i].Path))
		}
		return errors.Join(errs...)
	}
	for i, f := range tx.Files {
		touched = i + 1
		if f.Delete {
			err = nginx.Remove(f.Path)
			if os.IsNotExist(err) {
				err = nil
			}
		} else {
			if err = nginx.MkdirAll(filepath.Dir(f.Path), 0750); err == nil {
				err = writeTransactionFile(f.Path, []byte(f.Content))
			}
		}
		if err != nil {
			return config.RollbackError(err, restore)
		}
	}
	if err := b.testTransaction(); err != nil {
		return config.RollbackError(err, restore)
	}
	if err := b.reloadTransaction(); err != nil {
		return config.RollbackError(err, func() error {
			if err := restore(); err != nil {
				return err
			}
			if err := b.testTransaction(); err != nil {
				return err
			}
			return b.reloadTransaction()
		})
	}
	return nil
}

func (b *hostBackend) testTransaction() error {
	if b.transactionTest != nil {
		return b.transactionTest()
	}
	if r := nginx.Control(nginx.TestConfig); r.IsError() {
		return r.GetError()
	}
	return nil
}
func (b *hostBackend) reloadTransaction() error {
	if b.transactionReload != nil {
		return b.transactionReload()
	}
	if r := nginx.Control(nginx.Reload); r.IsError() {
		return r.GetError()
	}
	return nil
}

func readTransactionFile(path string) ([]byte, error) {
	f, err := nginx.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("existing configuration exceeds 1 MiB")
	}
	return data, nil
}

func writeTransactionFile(path string, content []byte) error {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(nonce[:])+".tmp")
	file, err := nginx.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer nginx.Remove(tmp)
	_, writeErr := file.Write(content)
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return nginx.Rename(tmp, path)
}
