package vault

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"nexvault/internal/nex"
)

func deriveIndexAEADKey(kIndex []byte) ([]byte, error) {
	if len(kIndex) != 32 {
		return nil, os.ErrInvalid
	}
	r := hkdf.New(sha3.New256, kIndex, nil, []byte("NEX:index:aead:v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func LoadIndexWithKey(indexPath string, kIndex []byte, vID string) (VaultIndex, error) {
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return VaultIndex{Entries: nil}, nil
		}
		return VaultIndex{}, err
	}

	min := 4 + nex.NonceSize + 16
	if len(raw) < min {
		return VaultIndex{}, nex.ErrCorrupt
	}
	if err := nex.CheckMagic(raw); err != nil {
		return VaultIndex{}, err
	}

	kAEAD, err := deriveIndexAEADKey(kIndex)
	if err != nil {
		return VaultIndex{}, err
	}
	defer nex.Wipe(kAEAD)

	aead, err := chacha20poly1305.NewX(kAEAD)
	if err != nil {
		return VaultIndex{}, err
	}

	nonce := raw[4 : 4+nex.NonceSize]
	ct := raw[4+nex.NonceSize:]
	pt, err := aead.Open(nil, nonce, ct, []byte("NEX:index:v1:"+vID+":index.nexi"))
	if err != nil {
		return VaultIndex{}, nex.ErrWrongKey
	}

	var idx VaultIndex
	if err := json.Unmarshal(pt, &idx); err != nil {
		return VaultIndex{}, nex.ErrCorrupt
	}
	if idx.Entries == nil {
		idx.Entries = nil
	}
	return idx, nil
}

func SyncIndexWithKey(indexPath string, kIndex []byte, vID string, idx VaultIndex) error {
	plain, err := json.Marshal(idx)
	if err != nil {
		return err
	}

	kAEAD, err := deriveIndexAEADKey(kIndex)
	if err != nil {
		return err
	}
	defer nex.Wipe(kAEAD)

	aead, err := chacha20poly1305.NewX(kAEAD)
	if err != nil {
		return err
	}

	nonce := make([]byte, nex.NonceSize)
	if err := nex.MustReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plain, []byte("NEX:index:v1:"+vID+":index.nexi"))

	out := append(nex.HeaderMagic(), append(nonce, ct...)...)
	return nex.WriteFileAtomic(indexPath, out)
}

func FindEntry(idx *VaultIndex, vRel string) int {
	for i := range idx.Entries {
		if idx.Entries[i].VaultRelPath == vRel {
			return i
		}
	}
	return -1
}
