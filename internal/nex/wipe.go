package nex

// wipe is best-effort only in Go; do not assume it defeats forensic memory analysis.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
