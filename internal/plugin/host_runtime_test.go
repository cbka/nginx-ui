package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeTransactionAtomicRollbackAndCAS(t *testing.T) {
	dir := t.TempDir()
	reloads := 0
	reject := false
	b := &hostBackend{confDir: func() string { return dir }, transactionTest: func() error {
		if reject {
			return errors.New("rejected")
		}
		return nil
	}, transactionReload: func() error { reloads++; return nil }}
	info, err := b.RuntimeInfo("io.example.rules")
	require.NoError(t, err)
	a := filepath.Join(info.PersistentDir, "a.conf")
	z := filepath.Join(info.PersistentDir, "b.conf")
	tx := ConfigTransaction{Reload: true, Files: []ConfigChange{{Path: a, Content: "one", ExpectedSHA256: "missing"}, {Path: z, Content: "two", ExpectedSHA256: "missing"}}}
	require.NoError(t, b.ApplyTransaction("io.example.rules", tx))
	require.Equal(t, 1, reloads)
	require.Error(t, b.ApplyTransaction("io.example.rules", tx))
	require.Equal(t, 1, reloads)
	sum := sha256.Sum256([]byte("one"))
	tx.Files = []ConfigChange{{Path: a, Content: "bad", ExpectedSHA256: hex.EncodeToString(sum[:])}, {Path: filepath.Join(info.PersistentDir, "new.conf"), Content: "bad", ExpectedSHA256: "missing"}}
	reject = true
	require.Error(t, b.ApplyTransaction("io.example.rules", tx))
	raw, err := os.ReadFile(a)
	require.NoError(t, err)
	require.Equal(t, "one", string(raw))
	_, err = os.Stat(tx.Files[1].Path)
	require.True(t, os.IsNotExist(err))
	require.Equal(t, 1, reloads)
}
func TestRuntimeTransactionRejectsEscapesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	b := &hostBackend{confDir: func() string { return dir }}
	info, err := b.RuntimeInfo("io.example.rules")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(info.PersistentDir, 0750))
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(info.PersistentDir, "link")))
	for _, path := range []string{filepath.Join(dir, "nginx.conf"), filepath.Join(info.PersistentDir, "link", "rule.conf"), filepath.Join(info.PersistentDir, "..", "other.conf")} {
		require.Error(t, b.ApplyTransaction("io.example.rules", ConfigTransaction{Reload: true, Files: []ConfigChange{{Path: path, Content: "x", ExpectedSHA256: "missing"}}}))
	}
}
func TestRuntimeTransactionReloadFailureRestoresRunningConfig(t *testing.T) {
	dir := t.TempDir()
	reloads := 0
	b := &hostBackend{confDir: func() string { return dir }, transactionTest: func() error { return nil }, transactionReload: func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload failure")
		}
		return nil
	}}
	info, err := b.RuntimeInfo("io.example.rules")
	require.NoError(t, err)
	path := filepath.Join(info.PersistentDir, "a.conf")
	require.Error(t, b.ApplyTransaction("io.example.rules", ConfigTransaction{Reload: true, Files: []ConfigChange{{Path: path, Content: "x", ExpectedSHA256: "missing"}}}))
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
	require.Equal(t, 2, reloads)
}
