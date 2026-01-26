package vault

import (
	"fmt"
	"time"
	"yap/internal/encoding"
)

const (
	HeaderMagic = "PMGRVAULT"
	HeaderVersion = 1
)

// ---- Header Structures ----

// VaultHeader represents the plaintext CBOR vault header.
// This header is NOT encrypted but IS authenticated via AAD.
type VaultHeader struct {
	Magic        string      `cbor:"magic"`
	Version      int         `cbor:"version"`
	KDF          KDFParams   `cbor:"kdf"`
	Crypto       CryptoParams `cbor:"crypto"`
	VaultID      string      `cbor:"vault_id"`
	KeyEpoch     uint64      `cbor:"key_epoch"`
	VaultVersion uint64      `cbor:"vault_version"`
	CreatedAt    int64       `cbor:"created_at"`
	LastModified int64       `cbor:"last_modified"`
}

type KDFParams struct {
	Algo        string `cbor:"algo"`
	Salt        []byte `cbor:"salt"`
	Memory      uint32 `cbor:"memory"`
	Iterations  uint32 `cbor:"iterations"`
	Parallelism uint8  `cbor:"parallelism"`
}

type CryptoParams struct {
	Cipher string `cbor:"cipher"`
}

// Validate enforces all invariants on the vault header.
// Any failure MUST abort vault opening.
func (h *VaultHeader) Validate() error {
	if h.Magic != HeaderMagic {
		return fmt.Errorf("invalid header magic")
	}

	if h.Version != HeaderVersion {
		return fmt.Errorf("unsupported header version: %d", h.Version)
	}

	if err := h.KDF.Validate(); err != nil {
		return fmt.Errorf("invalid kdf params: %w", err)
	}

	if err := h.Crypto.Validate(); err != nil {
		return fmt.Errorf("invalid crypto params: %w", err)
	}

	if h.VaultID == "" {
		return fmt.Errorf("vault_id must not be empty")
	}

	if h.KeyEpoch == 0 {
		return fmt.Errorf("key_epoch must be >= 1")
	}

	if h.VaultVersion == 0 {
		return fmt.Errorf("vault_version must be >= 1")
	}

	if h.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be set")
	}

	if h.LastModified < h.CreatedAt {
		return fmt.Errorf("last_modified < created_at")
	}

	// Optional sanity: timestamps not wildly in future
	now := time.Now().Unix()
	if h.CreatedAt > now+300 {
		return fmt.Errorf("created_at is in the future")
	}
	if h.LastModified > now+300 {
		return fmt.Errorf("last_modified is in the future")
	}

	return nil
}

func (k KDFParams) Validate() error {
	if k.Algo != "argon2id" {
		return fmt.Errorf("unsupported kdf algo: %s", k.Algo)
	}

	if len(k.Salt) < 16 || len(k.Salt) > 32 {
		return fmt.Errorf("salt length must be 16–32 bytes")
	}

	if k.Memory < 64*1024 {
		return fmt.Errorf("argon2 memory too low")
	}

	if k.Iterations < 1 {
		return fmt.Errorf("argon2 iterations must be >= 1")
	}

	if k.Parallelism < 1 {
		return fmt.Errorf("argon2 parallelism must be >= 1")
	}

	return nil
}

func (c CryptoParams) Validate() error {
	if c.Cipher != "xchacha20-poly1305" {
		return fmt.Errorf("unsupported cipher: %s", c.Cipher)
	}
	return nil
}

// CanonicalBytes returns the canonical CBOR encoding of the header.
// These bytes are used as AEAD AAD and MUST be identical across devices.
func (h *VaultHeader) CannonicalBytes() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
 
	return encoding.MarshalCanonical(h)
}

// DecodeVaultHeader decodes and validates a vault header from CBOR bytes.
func DecodeVaultHeader(data []byte) (*VaultHeader, error) {
	var h VaultHeader
	if err := encoding.UnmarshalStrict(data, &h); err != nil {
		return nil, fmt.Errorf("header decode failed: %w", err)
	}

	if err := h.Validate(); err != nil {
		return nil, err
	}

	return &h, nil
}
