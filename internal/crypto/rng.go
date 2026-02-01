/*
* RNG - Random number generator
* This file conntains code related to rng
* */

package crypto

import (
	"crypto/rand"
	"fmt"
)

// cryptographically secure random source
type RNG interface {
	Read([]byte) (int, error)
}

type SecureRNG struct{}

func (SecureRNG) Read(b []byte) (int, error) {
	n, err := rand.Read(b)
	if err != nil {
		return 0, fmt.Errorf("secure rng failure: %w", err)
	}
	if n != len(b) {
		return 0, fmt.Errorf("secure rng short read")
	}

	return n, nil
}
