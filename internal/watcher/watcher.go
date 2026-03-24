// Package watcher monitors a drop directory and automatically encrypts any
// regular file that lands in it into the vault, then securely wipes the
// plaintext from disk.
package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"nexvault/internal/nex"
	"nexvault/internal/vault"
)

const (
	// debounceInterval is the minimum quiet period (no new file-system events)
	// after which a file is considered fully written and ready to encrypt.
	// Large files that continue to receive write events will wait longer.
	debounceInterval = 500 * time.Millisecond

	// tickInterval controls how often the pending-file queue is checked.
	tickInterval = 200 * time.Millisecond
)

// Watcher monitors a drop directory and encrypts incoming files.
type Watcher struct {
	sess    *vault.Session
	dropDir string
	fsw     *fsnotify.Watcher
	log     func(string)

	mu      sync.Mutex
	pending map[string]time.Time // path -> time of last file-system event

	stopCh chan struct{}
	doneCh chan struct{}
}

// New creates a Watcher that will encrypt files from dropDir into sess.
// log is called with a human-readable status line for each significant event.
func New(sess *vault.Session, dropDir string, log func(string)) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{
		sess:    sess,
		dropDir: dropDir,
		fsw:     fsw,
		log:     log,
		pending: make(map[string]time.Time),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}, nil
}

// Start registers watchers on dropDir and all existing sub-directories, queues
// any files already present there, and starts the background goroutine.
// It is non-blocking; call Stop to shut down cleanly.
func (w *Watcher) Start() error {
	// Add the drop dir and every existing sub-directory to fsnotify.
	if err := filepath.WalkDir(w.dropDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate individual walk errors
		}
		if d.IsDir() {
			return w.fsw.Add(p)
		}
		return nil
	}); err != nil {
		return err
	}

	// Queue files that are already in the drop dir so they are processed on
	// the first tick after Start returns.
	w.scanExisting()

	go w.run()
	return nil
}

// Stop signals the watcher to shut down and waits for it to finish.
// Any files still pending at the time Stop is called are encrypted before
// the function returns.
func (w *Watcher) Stop() {
	close(w.stopCh)
	_ = w.fsw.Close()
	<-w.doneCh
}

// ── internal ────────────────────────────────────────────────────────────────

func (w *Watcher) scanExisting() {
	_ = filepath.WalkDir(w.dropDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() || w.shouldSkip(p) {
			return nil
		}
		w.mu.Lock()
		// Backdating makes the file immediately eligible on the first tick.
		w.pending[p] = time.Now().Add(-debounceInterval)
		w.mu.Unlock()
		return nil
	})
}

func (w *Watcher) run() {
	defer func() {
		// Final pass: encrypt anything still pending when Stop was called.
		w.flushAll()
		close(w.doneCh)
	}()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.handleEvent(event)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.log(fmt.Sprintf("[watcher error] %v", err))

		case <-ticker.C:
			w.processPending()

		case <-w.stopCh:
			return
		}
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	path := ev.Name

	info, err := os.Stat(path)
	if err != nil {
		// File is gone — remove from the pending queue.
		w.mu.Lock()
		delete(w.pending, path)
		w.mu.Unlock()
		return
	}

	if info.IsDir() {
		// Newly created directory: start watching it.
		if ev.Has(fsnotify.Create) {
			_ = w.fsw.Add(path)
		}
		return
	}

	if w.shouldSkip(path) {
		return
	}

	switch {
	case ev.Has(fsnotify.Create), ev.Has(fsnotify.Write), ev.Has(fsnotify.Rename):
		w.mu.Lock()
		w.pending[path] = time.Now()
		w.mu.Unlock()
	case ev.Has(fsnotify.Remove):
		w.mu.Lock()
		delete(w.pending, path)
		w.mu.Unlock()
	}
}

// processPending encrypts files that have been quiet for at least debounceInterval.
func (w *Watcher) processPending() {
	cutoff := time.Now().Add(-debounceInterval)
	w.mu.Lock()
	var ready []string
	for path, last := range w.pending {
		if last.Before(cutoff) {
			ready = append(ready, path)
			delete(w.pending, path)
		}
	}
	w.mu.Unlock()

	for _, path := range ready {
		w.encryptFile(path)
	}
}

// flushAll encrypts every file still in the pending queue regardless of debounce.
func (w *Watcher) flushAll() {
	w.mu.Lock()
	paths := make([]string, 0, len(w.pending))
	for path := range w.pending {
		paths = append(paths, path)
	}
	w.pending = make(map[string]time.Time)
	w.mu.Unlock()

	for _, path := range paths {
		w.encryptFile(path)
	}
}

func (w *Watcher) encryptFile(path string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || !info.Mode().IsRegular() {
		return
	}

	rel, err := filepath.Rel(w.dropDir, path)
	if err != nil {
		w.log(fmt.Sprintf("[skip] cannot relativise %s: %v", path, err))
		return
	}

	vRel, err := nex.NormalizeVaultRelPath(filepath.ToSlash(rel))
	if err != nil {
		w.log(fmt.Sprintf("[skip] invalid vault path %q: %v", rel, err))
		return
	}

	f, err := os.Open(path)
	if err != nil {
		w.log(fmt.Sprintf("[skip] open %s: %v", path, err))
		return
	}

	encErr := vault.UpsertStreamToVault(w.sess, vRel, f, info.Size())
	_ = f.Close()

	if encErr != nil {
		w.log(fmt.Sprintf("[error] encrypt %s: %v", vRel, encErr))
		return
	}

	// Overwrite the plaintext with zeros, then delete it.
	if wipeErr := secureDelete(path); wipeErr != nil {
		w.log(fmt.Sprintf("[warn] secure-delete %s: %v — falling back to plain delete", path, wipeErr))
		_ = os.Remove(path)
	}

	w.log(fmt.Sprintf("[encrypted] %s (%d bytes)", vRel, info.Size()))
}

// shouldSkip returns true for files that should not be encrypted:
// hidden files, editor swap/backup files, incomplete downloads, and vault internals.
func (w *Watcher) shouldSkip(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return true
	}
	lower := strings.ToLower(base)
	for _, suffix := range []string{".tmp", ".part", ".crdownload", "~"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	// Guard against the drop dir overlapping with the vault dir: skip anything
	// whose path relative to the drop dir starts with the ".nex" internal store.
	if rel, err := filepath.Rel(w.dropDir, path); err == nil {
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if top == ".nex" {
			return true
		}
	}
	return false
}

// secureDelete overwrites a file with zeros before removing it from the
// filesystem. O_NOFOLLOW prevents following a symlink that an attacker might
// have substituted between the encrypt and delete steps (TOCTOU defence).
// This wipe is best-effort: SSDs with wear-levelling may retain the old data
// in unmapped sectors.
func secureDelete(path string) error {
	// O_NOFOLLOW causes the open to fail with ELOOP if path is a symlink,
	// defending against a TOCTOU attack where an adversary swaps the plaintext
	// file for a symlink to a sensitive target between the encrypt and delete.
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	if size := info.Size(); size > 0 {
		const chunkSize = 64 * 1024
		zeros := make([]byte, chunkSize)
		remaining := size
		for remaining > 0 {
			toWrite := int64(len(zeros))
			if toWrite > remaining {
				toWrite = remaining
			}
			n, werr := f.Write(zeros[:toWrite])
			remaining -= int64(n)
			if werr != nil {
				break
			}
		}
		_ = f.Sync()
	}
	_ = f.Close()
	return os.Remove(path)
}
