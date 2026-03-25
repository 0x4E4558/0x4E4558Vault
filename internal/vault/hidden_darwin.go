//go:build darwin

package vault

import "syscall"

// HideDirectory sets the macOS UF_HIDDEN flag on dir so that Finder and
// standard open-panel dialogs no longer display it. The directory remains
// fully accessible by path, which is how nexvault re-opens it on subsequent
// sessions.
func HideDirectory(dir string) error {
	// UF_HIDDEN = 0x8000, defined in <sys/stat.h>. Go's syscall package does
	// not export this constant, so we use the numeric literal directly.
	const ufHidden = 0x8000
	return syscall.Chflags(dir, ufHidden)
}
