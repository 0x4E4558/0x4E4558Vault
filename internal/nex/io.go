package nex

import "io"

func MustReadFull(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	return err
}
