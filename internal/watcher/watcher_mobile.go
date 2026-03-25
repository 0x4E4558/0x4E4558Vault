//go:build android || ios

// Package watcher provides a no-op drop-folder watcher for mobile platforms.
// On Android and iOS, files are imported into the vault explicitly through the
// "Import File…" button in the UI rather than by watching a directory.
package watcher

import "nexvault/internal/vault"

// Watcher is a no-op stub on Android and iOS.
type Watcher struct{}

// New returns a no-op Watcher on mobile platforms.
func New(_ *vault.Session, _ string, _ func(string)) (*Watcher, error) {
	return &Watcher{}, nil
}

// Start is a no-op on mobile platforms.
func (w *Watcher) Start() error { return nil }

// Stop is a no-op on mobile platforms.
func (w *Watcher) Stop() {}
