package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	HKDFHashSize = 32 // SHA-256 output size
)

// HKDFExpand derives a context-specific key from a PRK using HKDF-SHA256.
//
// prk: Pseudorandom key (Argon2id output in our design)
// info: Domain separation string (must be non-empty)
// length: Number of bytes to derive
func HKDFExpand(prk []byte, info []byte, length int) ([]byte, error) {
	if len(prk) == 0 {
		return nil, fmt.Errorf("hkdf: prk must not be empty")
	}
	if len(info) == 0 {
		return nil, fmt.Errorf("hkdf: info must not be empty")
	}
	if length <= 0 {
		return nil, fmt.Errorf("hkdf: invalid length")
	}

	// No salt: Argon2id output is already a strong PRK
	reader := hkdf.New(sha256.New, prk, nil, info)

	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("hkdf expand failed: %w", err)
	}

	return out, nil
}


// Usage
// Derive Vault Key
// vk, err := crypto.HKDFExpand(
// 	masterKey,
// 	[]byte("pmgr:vault-key"),
// 	32,
// )
//
// Derive KEK (Vault Key wrapping)
// kek, err := crypto.HKDFExpand(
// 	masterKey,
// 	[]byte("pmgr:vault-key-wrap"),
// 	32,
// )
//
// Derive Entry Key context (if ever needed)
// ekCtx := []byte("pmgr:entry-key:" + entryID.String())

