package vault

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"nexvault/internal/nex"
)

func EnsureBlobStore(vaultPath string) (string, error) {
	root := filepath.Join(vaultPath, ".nex", "blobs")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	return root, nil
}

func NewBlobName() (string, error) {
	id := make([]byte, 16)
	if err := nex.MustReadFull(rand.Reader, id); err != nil {
		return "", err
	}
	hexID := hex.EncodeToString(id)
	return filepath.ToSlash(filepath.Join(".nex", "blobs", hexID[:2], hexID+".nex")), nil
}
