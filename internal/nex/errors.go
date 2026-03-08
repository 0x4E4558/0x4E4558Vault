package nex

import "errors"

var (
	ErrCorrupt  = errors.New("0x4E4558: corrupt or truncated data")
	ErrWrongKey = errors.New("0x4E4558: authentication failed")
)
