//go:build !android && !ios

package ui

import "fyne.io/fyne/v2"

// defaultVaultDir returns an empty string on desktop: the user picks the
// vault folder via the Browse dialog or types it manually.
func defaultVaultDir(_ fyne.App) string { return "" }

// defaultDropDir returns an empty string on desktop: the user picks the
// drop folder via the Browse dialog or types it manually.
func defaultDropDir(_ fyne.App) string { return "" }
