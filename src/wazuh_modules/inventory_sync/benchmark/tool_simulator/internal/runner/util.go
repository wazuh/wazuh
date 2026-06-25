package runner

import (
	"crypto/rand"
	"encoding/hex"
)

// randHex12 returns 12 random hex characters. Used as the unique suffix
// of bench-NNNN-XXXXXXXXXXXX agent names.
func randHex12() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
