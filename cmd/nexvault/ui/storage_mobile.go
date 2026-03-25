//go:build android || ios

package ui

import (
	"path/filepath"

	"fyne.io/fyne/v2"
)

// defaultVaultDir returns the app-private vault directory on Android/iOS.
// Using app storage guarantees write access under Android 10+ scoped storage
// and iOS sandboxing without requiring any additional permissions.
func defaultVaultDir(a fyne.App) string {
	return filepath.Join(a.Storage().RootURI().Path(), "vault")
}

// defaultDropDir returns the app-private drop directory on Android/iOS.
// The drop-folder watcher is a no-op on mobile; this path is kept to satisfy
// the startSession contract and may be used for future explicit imports.
func defaultDropDir(a fyne.App) string {
	return filepath.Join(a.Storage().RootURI().Path(), "drop")
}
