package vault

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"nexvault/internal/nex"
)

func derivePerBlobKeyV2(kRoot []byte, salt []byte) ([]byte, error) {
	if len(kRoot) != 32 {
		return nil, fmt.Errorf("invalid KBlobRoot length")
	}
	if len(salt) != nex.BlobSaltSize {
		return nil, nex.ErrCorrupt
	}
	r := hkdf.New(sha3.New256, kRoot, salt, []byte("NEX:blobkey:v2"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func chunkAADV2(vID, relPath string, gen uint64, chunkIndex uint64) []byte {
	prefix := []byte("NEX:blob:v2:")
	// Length-prefix vID and relPath to prevent AAD collisions when either
	// field contains the separator character.
	// Buffer: prefix + 4-byte len(vID) + vID + 4-byte len(relPath) + relPath +
	//         8-byte gen (uint64) + 8-byte chunkIndex (uint64)
	buf := make([]byte, len(prefix)+4+len(vID)+4+len(relPath)+16)
	off := 0
	off += copy(buf[off:], prefix)
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(vID)))
	off += 4
	off += copy(buf[off:], vID)
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(relPath)))
	off += 4
	off += copy(buf[off:], relPath)
	binary.LittleEndian.PutUint64(buf[off:], gen)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], chunkIndex)
	return buf
}

func nonceForChunk(base []byte, chunkIndex uint64) []byte {
	n := make([]byte, nex.NonceSize)
	copy(n, base)
	binary.LittleEndian.PutUint64(n[nex.NonceSize-8:], chunkIndex)
	return n
}

// Blob v2 format:
//
// [MAGIC(4)]
// [BLOB_FORMAT(u8)]                 // must be nex.BlobFormatV2
// [SALT(32)]
// [BASE_NONCE(24)]
// [CHUNK_SIZE(u32 LE)]              // must be nex.ChunkSize
// [FRAMES...]
//   [CHUNK_INDEX(u64 LE)]           // must start at 0 and increment by 1
//   [PLAIN_LEN(u32 LE)]             // 1..ChunkSize for data frames, 0 for terminator
//   [CIPHERTEXT(PLAIN_LEN + 16)]    // if PLAIN_LEN > 0
// Terminator:
//   [CHUNK_INDEX == next expected]
//   [PLAIN_LEN == 0]
//   (no ciphertext)
// After terminator: must be EOF.

func EncryptBlobStreamV2(kRoot []byte, vID, relPath string, gen uint64, r io.Reader, w io.Writer) (plainTotal int64, err error) {
	salt := make([]byte, nex.BlobSaltSize)
	if err := nex.MustReadFull(rand.Reader, salt); err != nil {
		return 0, err
	}
	baseNonce := make([]byte, nex.NonceSize)
	if err := nex.MustReadFull(rand.Reader, baseNonce); err != nil {
		return 0, err
	}

	key, err := derivePerBlobKeyV2(kRoot, salt)
	if err != nil {
		return 0, err
	}
	defer nex.Wipe(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, err
	}

	// Header
	if _, err := w.Write(nex.HeaderMagic()); err != nil {
		return 0, err
	}
	if _, err := w.Write([]byte{nex.BlobFormatV2}); err != nil {
		return 0, err
	}
	if _, err := w.Write(salt); err != nil {
		return 0, err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return 0, err
	}
	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], uint32(nex.ChunkSize))
	if _, err := w.Write(cs[:]); err != nil {
		return 0, err
	}

	br := bufio.NewReaderSize(r, nex.ChunkSize)
	buf := make([]byte, nex.ChunkSize)
	var idx uint64

	for {
		n, rerr := io.ReadFull(br, buf)
		if rerr == io.EOF {
			break
		}
		if rerr == io.ErrUnexpectedEOF {
			// last chunk
		} else if rerr != nil {
			return plainTotal, rerr
		}

		if n <= 0 || n > nex.ChunkSize {
			return plainTotal, nex.ErrCorrupt
		}

		plainChunk := buf[:n]
		plainTotal += int64(n)

		nonce := nonceForChunk(baseNonce, idx)
		aad := chunkAADV2(vID, relPath, gen, idx)
		ct := aead.Seal(nil, nonce, plainChunk, aad)

		var frameHdr [12]byte
		binary.LittleEndian.PutUint64(frameHdr[0:8], idx)
		binary.LittleEndian.PutUint32(frameHdr[8:12], uint32(n))

		if _, err := w.Write(frameHdr[:]); err != nil {
			return plainTotal, err
		}
		if _, err := w.Write(ct); err != nil {
			return plainTotal, err
		}

		idx++
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}

	// Terminator frame
	var term [12]byte
	binary.LittleEndian.PutUint64(term[0:8], idx)
	binary.LittleEndian.PutUint32(term[8:12], 0)
	if _, err := w.Write(term[:]); err != nil {
		return plainTotal, err
	}

	return plainTotal, nil
}

func DecryptBlobStreamV2(kRoot []byte, vID, relPath string, gen uint64, r io.Reader, w io.Writer) (plainTotal int64, err error) {
	// Magic
	h := make([]byte, 4)
	if err := nex.MustReadFull(r, h); err != nil {
		return 0, err
	}
	if err := nex.CheckMagic(h); err != nil {
		return 0, err
	}

	// Blob format
	var fmtB [1]byte
	if err := nex.MustReadFull(r, fmtB[:]); err != nil {
		return 0, err
	}
	if fmtB[0] != nex.BlobFormatV2 {
		return 0, fmt.Errorf("unsupported blob format: %d", fmtB[0])
	}

	// Rest header
	salt := make([]byte, nex.BlobSaltSize)
	if err := nex.MustReadFull(r, salt); err != nil {
		return 0, err
	}
	baseNonce := make([]byte, nex.NonceSize)
	if err := nex.MustReadFull(r, baseNonce); err != nil {
		return 0, err
	}
	var cs [4]byte
	if err := nex.MustReadFull(r, cs[:]); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(cs[:]) != uint32(nex.ChunkSize) {
		return 0, fmt.Errorf("unsupported chunk size in blob")
	}

	key, err := derivePerBlobKeyV2(kRoot, salt)
	if err != nil {
		return 0, err
	}
	defer nex.Wipe(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, err
	}

	ctBuf := make([]byte, nex.ChunkSize+aead.Overhead())
	var expected uint64 = 0

	for {
		var frameHdr [12]byte
		_, herr := io.ReadFull(r, frameHdr[:])
		if herr == io.EOF || herr == io.ErrUnexpectedEOF {
			// Must have terminator; EOF here means truncation.
			return plainTotal, nex.ErrCorrupt
		}
		if herr != nil {
			return plainTotal, herr
		}

		chunkIndex := binary.LittleEndian.Uint64(frameHdr[0:8])
		plainLen := binary.LittleEndian.Uint32(frameHdr[8:12])

		if chunkIndex != expected {
			return plainTotal, nex.ErrCorrupt
		}

		if plainLen == 0 {
			// Terminator: require clean EOF
			var one [1]byte
			n, _ := r.Read(one[:])
			if n != 0 {
				return plainTotal, nex.ErrCorrupt
			}
			return plainTotal, nil
		}

		if plainLen > uint32(nex.ChunkSize) {
			return plainTotal, nex.ErrCorrupt
		}

		ctLen := int(plainLen) + aead.Overhead()
		ct := ctBuf[:ctLen]
		if err := nex.MustReadFull(r, ct); err != nil {
			return plainTotal, nex.ErrCorrupt
		}

		nonce := nonceForChunk(baseNonce, chunkIndex)
		aad := chunkAADV2(vID, relPath, gen, chunkIndex)
		pt, err := aead.Open(nil, nonce, ct, aad)
		if err != nil {
			return plainTotal, nex.ErrWrongKey
		}

		if uint32(len(pt)) != plainLen {
			nex.Wipe(pt)
			return plainTotal, nex.ErrCorrupt
		}

		if _, err := w.Write(pt); err != nil {
			nex.Wipe(pt)
			return plainTotal, err
		}
		plainTotal += int64(len(pt))
		nex.Wipe(pt)
		expected++
	}
}
