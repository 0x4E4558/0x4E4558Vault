//go:build !darwin && !windows

package vault

// HideDirectory is a no-op on platforms where the OS does not support
// attribute-based directory hiding (Linux, Android, iOS). On Linux the
// conventional way to hide a folder is a leading dot in the name; on Android
// and iOS the app's private storage is already inaccessible to other apps.
func HideDirectory(_ string) error { return nil }
