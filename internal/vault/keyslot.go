package vault

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"nexvault/internal/nex"
)

func WriteKeyslot(path string, kPass []byte, vmk []byte) error {
	if len(vmk) != nex.VMKSize {
		return fmt.Errorf("invalid VMK size")
	}
	aead, err := chacha20poly1305.NewX(kPass)
	if err != nil {
		return err
	}
	nonce := make([]byte, nex.NonceSize)
	if err := nex.MustReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, vmk, []byte("NEX:keyslot:v1"))
	out := append(nex.HeaderMagic(), append(nonce, ct...)...)
	return nex.WriteFileAtomic(path, out)
}

func ReadKeyslot(path string, kPass []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	min := 4 + nex.NonceSize + nex.VMKSize + 16
	if len(raw) < min {
		return nil, nex.ErrCorrupt
	}
	if err := nex.CheckMagic(raw); err != nil {
		return nil, err
	}

	nonce := raw[4 : 4+nex.NonceSize]
	ct := raw[4+nex.NonceSize:]

	aead, err := chacha20poly1305.NewX(kPass)
	if err != nil {
		return nil, err
	}
	vmk, err := aead.Open(nil, nonce, ct, []byte("NEX:keyslot:v1"))
	if err != nil {
		return nil, nex.ErrWrongKey
	}
	if len(vmk) != nex.VMKSize {
		nex.Wipe(vmk)
		return nil, nex.ErrCorrupt
	}
	return vmk, nil
}
