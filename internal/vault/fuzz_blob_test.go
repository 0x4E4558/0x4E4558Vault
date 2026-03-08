package vault

import (
	"bytes"
	"testing"
)

func FuzzDecryptBlobStreamV2(f *testing.F) {
	kRoot := make([]byte, 32)
	for i := range kRoot {
		kRoot[i] = byte(i)
	}
	vID := "vid-test"
	rel := "docs/a.txt"
	gen := uint64(1)

	var blob bytes.Buffer
	_, _ = EncryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader([]byte("hello fuzz")), &blob)

	f.Add(blob.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_, _ = DecryptBlobStreamV2(kRoot, vID, rel, gen, bytes.NewReader(data), &out)
	})
}
