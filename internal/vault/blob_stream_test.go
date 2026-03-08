package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func TestEncryptDecrypt_RoundTrip_Sizes(t *testing.T) {
	kRoot := randBytes(32)
	vID := "vid-test"
	rel := "docs/a.txt"
	gen := uint64(1)

	sizes := []int{
		0, 1, 15, 16, 17,
		1<<20 - 1,
		1 << 20,
		1<<20 + 1,
		2*(1<<20) + 123,
	}

	for _, sz := range sizes {
		plain := randBytes(sz)
		var blob bytes.Buffer

		n, err := EncryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(plain), &blob)
		if err != nil {
			t.Fatalf("encrypt size=%d: %v", sz, err)
		}
		if int(n) != sz {
			t.Fatalf("encrypt size=%d: reported=%d", sz, n)
		}

		var out bytes.Buffer
		n2, err := DecryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(blob.Bytes()), &out)
		if err != nil {
			t.Fatalf("decrypt size=%d: %v", sz, err)
		}
		if int(n2) != sz {
			t.Fatalf("decrypt size=%d: reported=%d", sz, n2)
		}
		if !bytes.Equal(plain, out.Bytes()) {
			t.Fatalf("mismatch size=%d", sz)
		}
	}
}

func TestDecrypt_Truncated(t *testing.T) {
	kRoot := randBytes(32)
	vID := "vid-test"
	rel := "docs/a.txt"
	gen := uint64(1)

	plain := randBytes((1 << 20) + 10)
	var blob bytes.Buffer
	_, err := EncryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(plain), &blob)
	if err != nil {
		t.Fatal(err)
	}

	b := blob.Bytes()
	if len(b) < 50 {
		t.Fatal("blob too small")
	}
	trunc := b[:len(b)-7]

	var out bytes.Buffer
	_, err = DecryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(trunc), &out)
	if err == nil {
		t.Fatal("expected error on truncated blob")
	}
}

func TestDecrypt_BadChunkIndexSequence(t *testing.T) {
	kRoot := randBytes(32)
	vID := "vid-test"
	rel := "docs/a.txt"
	gen := uint64(1)

	plain := randBytes((1 << 20) + 10)
	var blob bytes.Buffer
	_, err := EncryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(plain), &blob)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the first frame chunk index in-place (after header).
	b := blob.Bytes()

	// Header len: magic(4)+fmt(1)+salt(32)+nonce(24)+chunksize(4)=65 bytes
	const hdrLen = 4 + 1 + 32 + 24 + 4
	if len(b) < hdrLen+8 {
		t.Fatal("blob too small")
	}

	// frameHdr: chunkIndex u64 at offset hdrLen
	bad := make([]byte, len(b))
	copy(bad, b)
	binary.LittleEndian.PutUint64(bad[hdrLen:hdrLen+8], 5)

	var out bytes.Buffer
	_, err = DecryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(bad), &out)
	if err == nil {
		t.Fatal("expected error on bad index sequence")
	}
}
