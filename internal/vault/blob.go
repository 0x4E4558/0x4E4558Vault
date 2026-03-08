package vault

import (
	"io"
)

// Currently we only support blob v2. Keeping this wrapper makes future upgrades easy.
func EncryptBlobStream(kRoot []byte, vID, relPath string, gen uint64, r io.Reader, w io.Writer) (int64, error) {
	return EncryptBlobStreamV2(kRoot, vID, relPath, gen, r, w)
}

func DecryptBlobStream(kRoot []byte, vID, relPath string, gen uint64, r io.Reader, w io.Writer) (int64, error) {
	return DecryptBlobStreamV2(kRoot, vID, relPath, gen, r, w)
}
