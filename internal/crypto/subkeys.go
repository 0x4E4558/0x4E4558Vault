package crypto

import (
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"nexvault/internal/nex"
)

func DeriveSubkeysFromVMK(vmk []byte) (kIndex, kBlobRoot []byte, err error) {
	r := hkdf.New(sha3.New256, vmk, nil, []byte("0x4E4558-V1-DOMAIN"))
	kIndex = make([]byte, 32)
	kBlobRoot = make([]byte, 32)
	if _, err := io.ReadFull(r, kIndex); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, kBlobRoot); err != nil {
		nex.Wipe(kIndex)
		return nil, nil, err
	}
	return kIndex, kBlobRoot, nil
}
