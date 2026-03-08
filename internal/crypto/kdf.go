package crypto

import (
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"

	"nexvault/internal/nex"
)

type KDFParams struct {
	MemKiB  uint32 `json:"mem_kib"`
	Time    uint32 `json:"time"`
	Threads uint8  `json:"threads"`
}

func safeThreads() uint8 {
	t := runtime.GOMAXPROCS(0)
	if t < 1 {
		t = 1
	}
	if t > nex.ArgonThreadsMax {
		t = nex.ArgonThreadsMax
	}
	return uint8(t)
}

func ClampKDF(p KDFParams) (KDFParams, error) {
	if p.MemKiB == 0 {
		p.MemKiB = nex.ArgonMemDefaultKiB
	}
	if p.MemKiB > nex.ArgonMemMaxKiB {
		return KDFParams{}, fmt.Errorf("kdf mem too high: %d KiB", p.MemKiB)
	}

	if p.Time == 0 {
		p.Time = nex.ArgonTimeDefault
	}
	if p.Time > nex.ArgonTimeMax {
		return KDFParams{}, fmt.Errorf("kdf time too high: %d", p.Time)
	}

	if p.Threads == 0 {
		p.Threads = safeThreads()
	}
	if p.Threads > nex.ArgonThreadsMax {
		return KDFParams{}, fmt.Errorf("kdf threads too high: %d", p.Threads)
	}
	return p, nil
}

func DeriveKPass(pass string, salt []byte, kdf KDFParams) ([]byte, error) {
	if len(salt) != nex.VaultSaltSize {
		return nil, nex.ErrCorrupt
	}
	kdf2, err := ClampKDF(kdf)
	if err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(pass), salt, kdf2.Time, kdf2.MemKiB, kdf2.Threads, 32), nil
}
