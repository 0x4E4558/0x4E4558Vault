package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"nexvault/internal/nex"
)

type DirImportPolicy int

const (
	DirImportSkipExisting DirImportPolicy = iota
	DirImportReplaceExisting
)

type DirImportProgress struct {
	FilesSeen     int64
	FilesImported int64
	FilesSkipped  int64
	Errors        int64

	current atomic.Value // string
}

func (p *DirImportProgress) SetCurrent(s string) { p.current.Store(s) }
func (p *DirImportProgress) Current() string {
	if v := p.current.Load(); v != nil {
		return v.(string)
	}
	return ""
}

func computeVaultBaseForFolder(selectedFolderPath string) (string, error) {
	base := filepath.Base(selectedFolderPath)
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return "", errors.New("invalid folder name")
	}
	return nex.NormalizeVaultRelPath(base)
}

// 1A mapping: vault root includes the folder name itself.
func ImportDirectory(sess *Session, rootDir string, policy DirImportPolicy, cancel *atomic.Bool, progress *DirImportProgress) error {
	info, err := os.Stat(rootDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("selected path is not a directory")
	}

	vaultBase, err := computeVaultBaseForFolder(rootDir)
	if err != nil {
		return err
	}

	return filepath.WalkDir(rootDir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			atomic.AddInt64(&progress.Errors, 1)
			return nil
		}
		if cancel.Load() {
			return errors.New("cancelled")
		}
		if d.IsDir() {
			return nil
		}

		// Skip symlinks for safety.
		if d.Type()&os.ModeSymlink != 0 {
			atomic.AddInt64(&progress.FilesSkipped, 1)
			return nil
		}
		if !d.Type().IsRegular() {
			atomic.AddInt64(&progress.FilesSkipped, 1)
			return nil
		}

		atomic.AddInt64(&progress.FilesSeen, 1)
		progress.SetCurrent(p)

		rel, err := filepath.Rel(rootDir, p)
		if err != nil {
			atomic.AddInt64(&progress.Errors, 1)
			return nil
		}

		vRel := filepath.ToSlash(filepath.Join(vaultBase, rel))
		vRel, err = nex.NormalizeVaultRelPath(vRel)
		if err != nil {
			atomic.AddInt64(&progress.Errors, 1)
			return nil
		}

		// Size hint (best effort)
		sizeHint := int64(-1)
		if fi, err := os.Stat(p); err == nil {
			sizeHint = fi.Size()
		}

		// Skip-existing policy checks the index.
		if policy == DirImportSkipExisting {
			idx, err := loadIndexLocked(sess)
			if err != nil {
				atomic.AddInt64(&progress.Errors, 1)
				return nil
			}
			if FindEntry(&idx, vRel) != -1 {
				atomic.AddInt64(&progress.FilesSkipped, 1)
				return nil
			}
		}

		f, err := os.Open(p)
		if err != nil {
			atomic.AddInt64(&progress.Errors, 1)
			return nil
		}
		defer func() { _ = f.Close() }()

		replace := policy == DirImportReplaceExisting
		if err := PutStreamToVault(sess, vRel, f, sizeHint, replace); err != nil {
			// Replace mode: if entry doesn't exist, create it instead of failing.
			if replace && strings.Contains(err.Error(), "cannot replace; entry does not exist") {
				_ = f.Close()
				f2, err2 := os.Open(p)
				if err2 != nil {
					atomic.AddInt64(&progress.Errors, 1)
					return nil
				}
				defer func() { _ = f2.Close() }()
				if err := PutStreamToVault(sess, vRel, f2, sizeHint, false); err != nil {
					atomic.AddInt64(&progress.Errors, 1)
					return nil
				}
				atomic.AddInt64(&progress.FilesImported, 1)
				return nil
			}

			atomic.AddInt64(&progress.Errors, 1)
			return nil
		}

		atomic.AddInt64(&progress.FilesImported, 1)
		return nil
	})
}
