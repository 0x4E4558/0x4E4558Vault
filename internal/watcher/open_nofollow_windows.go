//go:build windows

package watcher

import "os"

// openFileNoFollow opens path for writing. On Windows O_NOFOLLOW does not
// exist; the file is opened without symlink defence. Symlink creation on
// Windows requires SeCreateSymbolicLinkPrivilege (admin/dev-mode), so the
// TOCTOU risk is substantially lower than on Unix systems.
func openFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY, 0)
}
