package util

import (
	"fmt"
	"math/rand"
	"time"
)

const keyIDlen = 16
const keyIDchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

// Initialize random for GenerateKeyID()
func init() {
	rand.Seed(time.Now().UnixNano())
}

// GenerateKeyID generates a key ID for SAK that will be returned by
// backend.getSecretKey(), to identify each secret returned by the plugin.
//
// We need our own identifier since the plugin does not have access to lease IDs
// during secret generation and revocation.
func GenerateKeyID() string {
	b := make([]byte, keyIDlen)

	for i := range b {
		b[i] = keyIDchars[rand.Intn(len(keyIDchars))]
	}

	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), b)
}
