//go:build !android && !ios

package ui

import "fyne.io/fyne/v2"

const prefKeyVaultDir = "lastVaultDir"
const prefKeyDropDir = "lastDropDir"

// defaultVaultDir returns the last-used vault path from persistent preferences,
// or an empty string on first launch. The user is always free to change it.
func defaultVaultDir(a fyne.App) string {
	return a.Preferences().String(prefKeyVaultDir)
}

// defaultDropDir returns the last-used drop-folder path from persistent
// preferences, or an empty string on first launch.
func defaultDropDir(a fyne.App) string {
	return a.Preferences().String(prefKeyDropDir)
}

// saveLastPaths persists vaultDir (and dropDir if non-empty) so that the Open
// dialog pre-fills the correct paths on the next launch. This avoids the user
// having to retype hidden-folder paths every session.
func saveLastPaths(a fyne.App, vaultDir, dropDir string) {
	if vaultDir != "" {
		a.Preferences().SetString(prefKeyVaultDir, vaultDir)
	}
	if dropDir != "" {
		a.Preferences().SetString(prefKeyDropDir, dropDir)
	}
}
