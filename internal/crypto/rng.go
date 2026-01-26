package crypto

import (
	"crypto/rand"
	"fmt"
)

// Cryptographically secure random source
type RNG interface {
	Read([]byte) (int, error)
}

type SecureRNG struct{}

func (SecureRNG) Read(b []byte) (int, error) {
	n, err := rand.Read(b)
	if err != nil {
		return 0, fmt.Errorf("Secure rng failure: %w", err)
	}
	if n != len(b) {
		return 0, fmt.Errorf("secure rng short read")
	}

	return n, nil
}
