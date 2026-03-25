//go:build !windows && !android && !ios

package watcher

import (
	"os"
	"syscall"
)

// openFileNoFollow opens path for writing, refusing to follow a symlink.
// O_NOFOLLOW causes the open to fail with ELOOP if path is a symlink,
// defending against a TOCTOU attack where an adversary swaps the plaintext
// file for a symlink to a sensitive target between the encrypt and delete steps.
func openFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
}
