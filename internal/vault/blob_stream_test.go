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

// TestChunkAADV2_NoCollision verifies that vID and relPath values that would
// produce the same string when joined with ":" are given distinct AADs.
func TestChunkAADV2_NoCollision(t *testing.T) {
	// "a:b" + "c" and "a" + "b:c" are identical under naive concatenation
	// but must produce different AADs under length-prefixed encoding.
	aad1 := chunkAADV2("a:b", "c", 0, 0)
	aad2 := chunkAADV2("a", "b:c", 0, 0)
	if bytes.Equal(aad1, aad2) {
		t.Fatal("AAD collision: different (vID, relPath) produced identical AAD")
	}
}

// TestChunkAADV2_DistinctPerField verifies that all AAD parameters contribute
// independently to the output.
func TestChunkAADV2_DistinctPerField(t *testing.T) {
	base := chunkAADV2("vid", "path/file.txt", 1, 0)
	cases := []struct {
		name string
		aad  []byte
	}{
		{"different vID", chunkAADV2("vid2", "path/file.txt", 1, 0)},
		{"different relPath", chunkAADV2("vid", "path/other.txt", 1, 0)},
		{"different gen", chunkAADV2("vid", "path/file.txt", 2, 0)},
		{"different chunkIndex", chunkAADV2("vid", "path/file.txt", 1, 1)},
	}
	for _, c := range cases {
		if bytes.Equal(base, c.aad) {
			t.Errorf("AAD collision for case %q", c.name)
		}
	}
}

// TestDecrypt_WrongVID verifies that a blob encrypted under one vaultID cannot
// be decrypted using a different vaultID, even if they share a separator.
func TestDecrypt_WrongVID(t *testing.T) {
	kRoot := randBytes(32)
	gen := uint64(1)
	relPath := "docs/secret.txt"
	plain := []byte("sensitive data")

	// Encrypt with vID "a:b"
	var blob bytes.Buffer
	_, err := EncryptBlobStreamV2(kRoot, "a:b", relPath, gen, bytes.NewReader(plain), &blob)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to decrypt with vID "a" and relPath "b:docs/secret.txt" - must fail.
	var out bytes.Buffer
	_, err = DecryptBlobStreamV2(kRoot, "a", "b:"+relPath, gen, bytes.NewReader(blob.Bytes()), &out)
	if err == nil {
		t.Fatal("expected decryption failure with wrong vID; AAD collision may be present")
	}
}

// TestDecrypt_WrongRelPath verifies that a blob cannot be decrypted using a
// different relPath, even one that would match under naive string concatenation.
func TestDecrypt_WrongRelPath(t *testing.T) {
	kRoot := randBytes(32)
	gen := uint64(1)
	vID := "vid-test"
	plain := []byte("other sensitive data")

	// Encrypt with relPath "a:b"
	var blob bytes.Buffer
	_, err := EncryptBlobStreamV2(kRoot, vID, "a:b", gen, bytes.NewReader(plain), &blob)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to decrypt with a different split - must fail.
	var out bytes.Buffer
	_, err = DecryptBlobStreamV2(kRoot, vID+":", "b", gen, bytes.NewReader(blob.Bytes()), &out)
	if err == nil {
		t.Fatal("expected decryption failure with wrong relPath; AAD collision may be present")
	}
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
