package audit

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRunID returns a 16-character hex string suitable for correlating
// a macnoise run across audit records and host telemetry.
func GenerateRunID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
