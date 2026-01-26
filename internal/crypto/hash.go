
package crypto

import (
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const HashSize = 32 // 256-bit

// Hash computes a BLAKE2b-256 hash.
func Hash(data []byte) ([]byte, error) {
	h, err := blake2b.New(HashSize, nil)
	if err != nil {
		return nil, fmt.Errorf("blake2b init failed: %w", err)
	}

	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("blake2b write failed: %w", err)
	}

	return h.Sum(nil), nil
}

// Usage pattern
//
// Generating nonce safely
// rng := crypto.SecureRNG{}
// nonce := make([]byte, crypto.XChaChaNonceSize)
// _, err := rng.Read(nonce)
//
// Encrypting
// ct, err := crypto.Encrypt(key, nonce, plaintext, aad)
