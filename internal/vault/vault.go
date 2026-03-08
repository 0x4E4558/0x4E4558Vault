package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nexvault/internal/crypto"
	"nexvault/internal/nex"
)

func CreateVault(dir, pass string) error {
	if pass == "" {
		return errors.New("empty passphrase not allowed")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	salt := make([]byte, nex.VaultSaltSize)
	vmk := make([]byte, nex.VMKSize)
	if err := nex.MustReadFull(rand.Reader, salt); err != nil {
		return err
	}
	if err := nex.MustReadFull(rand.Reader, vmk); err != nil {
		return err
	}
	defer nex.Wipe(vmk)

	vID := fmt.Sprintf("%x", time.Now().UnixNano())
	created := time.Now().Unix()
	kdf := crypto.KDFParams{MemKiB: nex.ArgonMemDefaultKiB, Time: nex.ArgonTimeDefault, Threads: 0}

	if err := WriteVaultHeaderV1(filepath.Join(dir, "vault.hdr"), pass, vID, created, salt, kdf); err != nil {
		return err
	}

	kPass, err := crypto.DeriveKPass(pass, salt, kdf)
	if err != nil {
		return err
	}
	defer nex.Wipe(kPass)

	if err := WriteKeyslot(filepath.Join(dir, "keyslot.nexk"), kPass, vmk); err != nil {
		return err
	}

	kIndex, kBlobRoot, err := crypto.DeriveSubkeysFromVMK(vmk)
	if err != nil {
		return err
	}
	defer nex.Wipe(kIndex)
	defer nex.Wipe(kBlobRoot)

	if err := SyncIndexWithKey(filepath.Join(dir, "index.nexi"), kIndex, vID, VaultIndex{Entries: nil}); err != nil {
		return err
	}

	if _, err := EnsureBlobStore(dir); err != nil {
		return err
	}

	return nil
}

func UnlockVault(sess *Session, dir, pass string) error {
	if pass == "" {
		return errors.New("empty passphrase not allowed")
	}

	vID, _, salt, kdf, err := ReadVaultHeaderV1(filepath.Join(dir, "vault.hdr"), pass)
	if err != nil {
		return err
	}

	kPass, err := crypto.DeriveKPass(pass, salt, kdf)
	if err != nil {
		return err
	}
	defer nex.Wipe(kPass)

	vmk, err := ReadKeyslot(filepath.Join(dir, "keyslot.nexk"), kPass)
	if err != nil {
		return err
	}
	defer nex.Wipe(vmk)

	kIndex, kBlobRoot, err := crypto.DeriveSubkeysFromVMK(vmk)
	if err != nil {
		return err
	}

	sess.Mutex.Lock()
	defer sess.Mutex.Unlock()

	// wipe previous
	if sess.KIndex != nil {
		nex.Wipe(sess.KIndex)
	}
	if sess.KBlobRoot != nil {
		nex.Wipe(sess.KBlobRoot)
	}

	sess.Active = true
	sess.VaultPath = dir
	sess.VaultID = vID
	sess.KIndex = kIndex
	sess.KBlobRoot = kBlobRoot

	return nil
}
