package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	icrypto "nexvault/internal/crypto"
	"nexvault/internal/nex"
)

type vaultHdrClear struct {
	Salt    [nex.VaultSaltSize]byte
	MemKiB  uint32
	Time    uint32
	Threads uint8
	Pad     [7]byte
}

type vaultHdrPlain struct {
	VaultID string `json:"vid"`
	Created int64  `json:"created"`
	V       uint8  `json:"v"`
}

func vaultHeaderAAD(clear vaultHdrClear) []byte {
	aad := new(bytes.Buffer)
	aad.Write(nex.HeaderMagic())
	_ = binary.Write(aad, binary.LittleEndian, clear.MemKiB)
	_ = binary.Write(aad, binary.LittleEndian, clear.Time)
	_ = aad.WriteByte(clear.Threads)
	aad.Write(clear.Salt[:])
	return aad.Bytes()
}

func WriteVaultHeaderV1(path string, pass string, vaultID string, created int64, salt []byte, kdf icrypto.KDFParams) error {
	if len(salt) != nex.VaultSaltSize {
		return fmt.Errorf("invalid salt length")
	}
	kdf2, err := icrypto.ClampKDF(kdf)
	if err != nil {
		return err
	}

	var clear vaultHdrClear
	copy(clear.Salt[:], salt)
	clear.MemKiB = kdf2.MemKiB
	clear.Time = kdf2.Time
	clear.Threads = kdf2.Threads

	plainBytes, err := json.Marshal(vaultHdrPlain{VaultID: vaultID, Created: created, V: nex.AppVersion})
	if err != nil {
		return err
	}

	kPass, err := icrypto.DeriveKPass(pass, clear.Salt[:], kdf2)
	if err != nil {
		return err
	}
	defer nex.Wipe(kPass)

	aead, err := chacha20poly1305.NewX(kPass)
	if err != nil {
		return err
	}

	nonce := make([]byte, nex.NonceSize)
	if err := nex.MustReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ct := aead.Seal(nil, nonce, plainBytes, vaultHeaderAAD(clear))

	out := new(bytes.Buffer)
	out.Write(nex.HeaderMagic())
	out.Write(clear.Salt[:])
	_ = binary.Write(out, binary.LittleEndian, clear.MemKiB)
	_ = binary.Write(out, binary.LittleEndian, clear.Time)
	_ = out.WriteByte(clear.Threads)
	out.Write(clear.Pad[:])
	out.Write(nonce)
	out.Write(ct)

	return nex.WriteFileAtomic(path, out.Bytes())
}

func ReadVaultHeaderV1(path string, pass string) (vaultID string, created int64, salt []byte, kdf icrypto.KDFParams, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, nil, icrypto.KDFParams{}, err
	}
	const clearSize = nex.VaultSaltSize + 4 + 4 + 1 + 7
	min := 4 + clearSize + nex.NonceSize + 16
	if len(raw) < min {
		return "", 0, nil, icrypto.KDFParams{}, nex.ErrCorrupt
	}
	if err := nex.CheckMagic(raw); err != nil {
		return "", 0, nil, icrypto.KDFParams{}, err
	}

	off := 4
	var clear vaultHdrClear
	copy(clear.Salt[:], raw[off:off+nex.VaultSaltSize])
	off += nex.VaultSaltSize

	clear.MemKiB = binary.LittleEndian.Uint32(raw[off : off+4])
	off += 4
	clear.Time = binary.LittleEndian.Uint32(raw[off : off+4])
	off += 4
	clear.Threads = raw[off]
	off += 1
	off += 7 // pad

	kdf2, err := icrypto.ClampKDF(icrypto.KDFParams{MemKiB: clear.MemKiB, Time: clear.Time, Threads: clear.Threads})
	if err != nil {
		return "", 0, nil, icrypto.KDFParams{}, err
	}

	nonce := raw[off : off+nex.NonceSize]
	off += nex.NonceSize
	ct := raw[off:]

	kPass, err := icrypto.DeriveKPass(pass, clear.Salt[:], kdf2)
	if err != nil {
		return "", 0, nil, icrypto.KDFParams{}, err
	}
	defer nex.Wipe(kPass)

	aead, err := chacha20poly1305.NewX(kPass)
	if err != nil {
		return "", 0, nil, icrypto.KDFParams{}, err
	}

	pt, err := aead.Open(nil, nonce, ct, vaultHeaderAAD(clear))
	if err != nil {
		return "", 0, nil, icrypto.KDFParams{}, nex.ErrWrongKey
	}

	var plain vaultHdrPlain
	if err := json.Unmarshal(pt, &plain); err != nil {
		return "", 0, nil, icrypto.KDFParams{}, nex.ErrCorrupt
	}
	if plain.V != nex.AppVersion {
		return "", 0, nil, icrypto.KDFParams{}, fmt.Errorf("unsupported inner header version: %d", plain.V)
	}

	return plain.VaultID, plain.Created, append([]byte(nil), clear.Salt[:]...), kdf2, nil
}
