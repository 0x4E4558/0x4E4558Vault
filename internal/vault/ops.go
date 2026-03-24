package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"nexvault/internal/nex"
)

func loadIndexLocked(sess *Session) (VaultIndex, error) {
	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return VaultIndex{}, errors.New("vault locked")
	}
	kI := append([]byte(nil), sess.KIndex...)
	vID := sess.VaultID
	vPath := sess.VaultPath
	sess.Mutex.RUnlock()
	defer nex.Wipe(kI)

	return LoadIndexWithKey(filepath.Join(vPath, "index.nexi"), kI, vID)
}

func syncIndexLocked(sess *Session, idx VaultIndex) error {
	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return errors.New("vault locked")
	}
	kI := append([]byte(nil), sess.KIndex...)
	vID := sess.VaultID
	vPath := sess.VaultPath
	sess.Mutex.RUnlock()
	defer nex.Wipe(kI)

	return SyncIndexWithKey(filepath.Join(vPath, "index.nexi"), kI, vID, idx)
}

func PutStreamToVault(sess *Session, vRel string, r io.Reader, sizeHint int64, replace bool) error {
	vRel, err := nex.NormalizeVaultRelPath(vRel)
	if err != nil {
		return err
	}

	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return errors.New("vault locked")
	}
	vPath := sess.VaultPath
	vID := sess.VaultID
	kRoot := append([]byte(nil), sess.KBlobRoot...)
	sess.Mutex.RUnlock()
	defer nex.Wipe(kRoot)

	if _, err := EnsureBlobStore(vPath); err != nil {
		return err
	}

	idx, err := loadIndexLocked(sess)
	if err != nil {
		return err
	}

	i := FindEntry(&idx, vRel)
	if i == -1 && replace {
		return fmt.Errorf("cannot replace; entry does not exist: %s", vRel)
	}
	if i != -1 && !replace {
		return fmt.Errorf("duplicate import disallowed: %s", vRel)
	}

	var gen uint64 = 1
	var oldBlob string
	if i != -1 {
		gen = idx.Entries[i].Gen + 1
		oldBlob = idx.Entries[i].BlobName
	}

	blobName, err := NewBlobName()
	if err != nil {
		return err
	}
	dest := filepath.Join(vPath, filepath.FromSlash(blobName))
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("internal collision (unexpected): %s", dest)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(dest)
		}
	}()

	plainTotal, err := EncryptBlobStream(kRoot, vID, vRel, gen, r, f)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true

	size := plainTotal
	if sizeHint >= 0 && sizeHint != plainTotal {
		size = plainTotal
	}

	entry := IndexEntry{
		VaultRelPath: vRel,
		BlobName:     blobName,
		Size:         size,
		Added:        time.Now().Unix(),
		Gen:          gen,
	}

	if i == -1 {
		idx.Entries = append(idx.Entries, entry)
	} else {
		idx.Entries[i] = entry
	}

	if err := syncIndexLocked(sess, idx); err != nil {
		return err
	}

	if replace && oldBlob != "" {
		_ = os.Remove(filepath.Join(vPath, filepath.FromSlash(oldBlob)))
	}

	return nil
}

func DecryptToWriterByVaultPath(sess *Session, vRel string, w io.Writer) (plainBytes int64, err error) {
	vRel, err = nex.NormalizeVaultRelPath(vRel)
	if err != nil {
		return 0, err
	}

	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return 0, errors.New("vault locked")
	}
	vPath := sess.VaultPath
	vID := sess.VaultID
	kRoot := append([]byte(nil), sess.KBlobRoot...)
	sess.Mutex.RUnlock()
	defer nex.Wipe(kRoot)

	idx, err := loadIndexLocked(sess)
	if err != nil {
		return 0, err
	}
	i := FindEntry(&idx, vRel)
	if i == -1 {
		return 0, fmt.Errorf("not found: %s", vRel)
	}
	e := idx.Entries[i]

	blobPath := filepath.Join(vPath, filepath.FromSlash(e.BlobName))
	f, err := os.Open(blobPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	return DecryptBlobStream(kRoot, vID, e.VaultRelPath, e.Gen, f, w)
}

// LoadIndexForSession returns the current vault index for the given session.
// It is safe for concurrent use.
func LoadIndexForSession(sess *Session) (VaultIndex, error) {
	return loadIndexLocked(sess)
}

// UpsertStreamToVault stores the data from r in the vault at vRel. If an entry
// with that path already exists it is atomically replaced; otherwise a new entry
// is created. It is safe for concurrent use.
func UpsertStreamToVault(sess *Session, vRel string, r io.Reader, sizeHint int64) error {
	vRel, err := nex.NormalizeVaultRelPath(vRel)
	if err != nil {
		return err
	}
	idx, err := loadIndexLocked(sess)
	if err != nil {
		return err
	}
	return PutStreamToVault(sess, vRel, r, sizeHint, FindEntry(&idx, vRel) != -1)
}

// DeleteEntries atomically removes multiple vault entries in a single index
// read/write cycle, making it efficient for bulk deletions. Entries that are
// not found in the index are silently skipped.
func DeleteEntries(sess *Session, vRels []string) error {
	if len(vRels) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(vRels))
	for _, vRel := range vRels {
		n, err := nex.NormalizeVaultRelPath(vRel)
		if err != nil {
			return err
		}
		normalized = append(normalized, n)
	}

	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return errors.New("vault locked")
	}
	vPath := sess.VaultPath
	sess.Mutex.RUnlock()

	idx, err := loadIndexLocked(sess)
	if err != nil {
		return err
	}

	toDelete := make(map[string]struct{}, len(normalized))
	for _, vRel := range normalized {
		toDelete[vRel] = struct{}{}
	}

	var blobsToRemove []string
	remaining := make([]IndexEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if _, del := toDelete[e.VaultRelPath]; del {
			blobsToRemove = append(blobsToRemove, e.BlobName)
		} else {
			remaining = append(remaining, e)
		}
	}

	idx.Entries = remaining
	if err := syncIndexLocked(sess, idx); err != nil {
		return err
	}

	for _, blob := range blobsToRemove {
		_ = os.Remove(filepath.Join(vPath, filepath.FromSlash(blob)))
	}
	return nil
}

func DeleteEntry(sess *Session, vRel string) error {
	vRel, err := nex.NormalizeVaultRelPath(vRel)
	if err != nil {
		return err
	}

	sess.Mutex.RLock()
	if !sess.Active {
		sess.Mutex.RUnlock()
		return errors.New("vault locked")
	}
	vPath := sess.VaultPath
	sess.Mutex.RUnlock()

	idx, err := loadIndexLocked(sess)
	if err != nil {
		return err
	}

	i := FindEntry(&idx, vRel)
	if i == -1 {
		return fmt.Errorf("not found: %s", vRel)
	}
	blobName := idx.Entries[i].BlobName

	idx.Entries = append(idx.Entries[:i], idx.Entries[i+1:]...)
	if err := syncIndexLocked(sess, idx); err != nil {
		return err
	}

	_ = os.Remove(filepath.Join(vPath, filepath.FromSlash(blobName)))
	return nil
}
