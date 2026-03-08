package nex

import "errors"

func HeaderMagic() []byte { return []byte{MB1, MB2, MB3, AppVersion} }

func CheckMagic(b []byte) error {
	if len(b) < 4 {
		return ErrCorrupt
	}
	if b[0] != MB1 || b[1] != MB2 || b[2] != MB3 {
		return errors.New("magic mismatch")
	}
	if b[3] != AppVersion {
		return errors.New("version mismatch")
	}
	return nil
}
