//go:build windows

package vault

import "syscall"

// HideDirectory sets the Windows FILE_ATTRIBUTE_HIDDEN flag on dir so that
// Explorer hides it from normal directory listings. The directory remains
// fully accessible by path, which is how nexvault re-opens it on subsequent
// sessions.
func HideDirectory(dir string) error {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(p, attrs|syscall.FILE_ATTRIBUTE_HIDDEN)
}
