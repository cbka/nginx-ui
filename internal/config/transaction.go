package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/0xJacky/Nginx-UI/internal/nginx"
)

// applyMutex serializes the write -> `nginx -t` -> reload sequence of every
// configuration mutation. `nginx -t` validates the whole configuration tree, so
// without this lock two concurrent saves would test each other's half applied
// files and roll back a change that is perfectly valid on its own.
var applyMutex sync.Mutex

// LockApply blocks until no other configuration mutation sits between its write
// and its reload, and returns the function that releases the lock.
func LockApply() (release func()) {
	applyMutex.Lock()
	return applyMutex.Unlock
}

// TryLockApply acquires the configuration apply lock without waiting. Control
// endpoints use it to fail fast instead of building an unbounded request queue
// behind a long-running configuration mutation.
func TryLockApply() (release func(), ok bool) {
	if !applyMutex.TryLock() {
		return nil, false
	}
	return applyMutex.Unlock, true
}

// FileSnapshot records the on-disk state of a configuration file so a failed
// nginx test or reload can put the previous state back. A snapshot taken of a
// missing file restores by removing the file again, which is what a newly
// created configuration needs.
//
// Every file operation goes through the nginx target filesystem, so the
// snapshot also covers configuration that lives on an SSH host reached over
// SFTP rather than on a local or bind-mounted directory.
type FileSnapshot struct {
	exists  bool
	content []byte
	mode    os.FileMode
}

// appliedFiles is conservative proof from a successful apply in this process.
// Callers coordinate mutations with LockApply. Clearing it causes an extra reload; it
// never permits an unapplied file to be skipped. A bounded cache avoids growth
// from repeated create/delete operations. Startup begins without any proof.
var appliedFilesMutex sync.Mutex
var appliedFiles = make(map[string][32]byte)

func RecordAppliedFile(path string, content []byte) {
	appliedFilesMutex.Lock()
	defer appliedFilesMutex.Unlock()
	if len(appliedFiles) >= 4096 {
		clear(appliedFiles)
	}
	appliedFiles[path] = sha256.Sum256(content)
}

func invalidateAppliedFiles() {
	appliedFilesMutex.Lock()
	defer appliedFilesMutex.Unlock()
	// A reload applies the whole tree: a staged include may affect another site.
	clear(appliedFiles)
}

// IsApplied checks both current disk contents and known successful application.
// It deliberately does not infer the running configuration from disk alone.
func (snapshot FileSnapshot) IsApplied(path string, content []byte) bool {
	appliedFilesMutex.Lock()
	defer appliedFilesMutex.Unlock()
	hash, known := appliedFiles[path]
	return known && snapshot.exists && bytes.Equal(snapshot.content, content) && hash == sha256.Sum256(content)
}

// CaptureFile snapshots the configuration file at path.
func CaptureFile(path string) (FileSnapshot, error) {
	content, err := nginx.ReadFile(path)
	if os.IsNotExist(err) {
		return FileSnapshot{}, nil
	}
	if err != nil {
		return FileSnapshot{}, err
	}

	info, err := nginx.Stat(path)
	if err != nil {
		return FileSnapshot{}, err
	}

	return FileSnapshot{
		exists:  true,
		content: content,
		mode:    info.Mode().Perm(),
	}, nil
}

// Restore puts the captured state back on disk. A snapshot of a file that did
// not exist removes the file the caller created.
func (snapshot FileSnapshot) Restore(path string) error {
	invalidateAppliedFiles()
	if !snapshot.exists {
		if err := nginx.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	return WriteFile(path, snapshot.content, snapshot.mode)
}

// WriteFile replaces the content of a configuration file in place to preserve
// symlink targets and file-level bind mounts. The caller keeps a snapshot and
// restores it when validation or reload fails.
func WriteFile(path string, content []byte, mode os.FileMode) error {
	invalidateAppliedFiles()
	return nginx.WriteFile(path, content, mode)
}

// RollbackError runs the rollback and reports the original failure, adding the
// rollback failure when the previous state could not be put back.
func RollbackError(primary error, rollback func() error) error {
	if err := rollback(); err != nil {
		return errors.Join(primary, fmt.Errorf("rollback failed: %w", err))
	}
	return primary
}

// RestoreAndReload puts the previous content back and makes the running Nginx
// use it again.
func RestoreAndReload(path string, snapshot FileSnapshot) error {
	if err := snapshot.Restore(path); err != nil {
		return err
	}

	return reloadRestored()
}

// reloadRestored validates and loads the configuration a rollback put back in
// place.
func reloadRestored() error {
	if result := nginx.Control(nginx.TestConfig); result.IsError() {
		return fmt.Errorf("test restored configuration: %w", result.GetError())
	}
	if result := nginx.Control(nginx.Reload); result.IsError() {
		return fmt.Errorf("reload restored configuration: %w", result.GetError())
	}

	return nil
}

// RemoveEnabledLink drops the symlink that enables a configuration. A link that
// is already gone is not an error: the desired state has been reached.
func RemoveEnabledLink(path string) error {
	if err := nginx.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RemoveEnabledLinkAndReload removes the enabled symlink and brings the running
// Nginx back to the configuration it served before the link was created. Use it
// when a reload has already been attempted with the link in place.
func RemoveEnabledLinkAndReload(path string) error {
	if err := RemoveEnabledLink(path); err != nil {
		return err
	}

	return reloadRestored()
}

// FileTransaction snapshots every file it writes so a rejected `nginx -t` can
// restore all of them, including removing the files the transaction created.
type FileTransaction struct {
	entries []fileTransactionEntry
}

type fileTransactionEntry struct {
	path     string
	snapshot FileSnapshot
	content  []byte
}

// Write snapshots path and then replaces its content.
func (t *FileTransaction) Write(path string, content []byte, mode os.FileMode) error {
	snapshot, err := CaptureFile(path)
	if err != nil {
		return err
	}

	t.entries = append(t.entries, fileTransactionEntry{path: path, snapshot: snapshot, content: append([]byte(nil), content...)})

	return WriteFile(path, content, mode)
}

// Len reports how many files the transaction has written.
func (t *FileTransaction) Len() int {
	return len(t.entries)
}

// Rollback restores every written file in reverse order and reports every
// restore failure it hit.
func (t *FileTransaction) Rollback() error {
	errs := make([]error, 0, len(t.entries))
	for i := len(t.entries) - 1; i >= 0; i-- {
		if err := t.entries[i].snapshot.Restore(t.entries[i].path); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// RollbackAndReload restores every written file and makes the running Nginx use
// the restored configuration again.
func (t *FileTransaction) RollbackAndReload() error {
	if err := t.Rollback(); err != nil {
		return err
	}

	return reloadRestored()
}

// TestAndReload validates the configuration on disk before reloading Nginx.
// A rejected configuration is rolled back, because the running Nginx keeps
// serving its old in-memory configuration and invalid content left on disk
// would only surface on the next Nginx start, when every vhost goes down.
func (t *FileTransaction) TestAndReload() error {
	if result := nginx.Control(nginx.TestConfig); result.IsError() {
		return RollbackError(result.GetError(), t.Rollback)
	}

	if result := nginx.Control(nginx.Reload); result.IsError() {
		return RollbackError(result.GetError(), t.RollbackAndReload)
	}
	for _, entry := range t.entries {
		RecordAppliedFile(entry.path, entry.content)
	}
	return nil
}
