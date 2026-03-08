package nex

import (
	"os"
	"path/filepath"
)

// Atomic write: write temp in same dir then rename.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmpF, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpF.Name()

	_ = tmpF.Chmod(0600)

	_, werr := tmpF.Write(data)
	cerr := tmpF.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return cerr
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
