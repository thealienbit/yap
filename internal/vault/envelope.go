package vault

import (
	"fmt"
	"yap/internal/crypto"
	"yap/internal/encoding"
)

// EncryptedEnvelope is the outer CBOR object that wraps encrypted payload.
type EncryptedEnvelope struct {
	Nonce      []byte `cbor:"nonce"`       // 24 bytes
	Ciphertext []byte `cbor:"ciphertext"`  // includes Poly1305 tag
}

// DecryptedPayload is the plaintext CBOR payload after decryption.
type DecryptedPayload struct {
	VaultMetadata   VaultMetadata   `cbor:"vault_metadata"`
	WrappedVaultKey WrappedVaultKey `cbor:"wrapped_vault_key"`
	SQLite          SQLitePayload   `cbor:"sqlite"`
}

type VaultMetadata struct {
	VaultID      string `cbor:"vault_id"`
	VaultVersion uint64 `cbor:"vault_version"`
	KeyEpoch     uint64 `cbor:"key_epoch"`

	DeviceID   string `cbor:"device_id"`
	CreatedBy  string `cbor:"created_by"`
	LastWriter string `cbor:"last_writer"`
 
	Integrity IntegrityBlock `cbor:"integrity"`
}

type IntegrityBlock struct {
	PayloadHash []byte `cbor:"payload_hash"` // BLAKE2b-256
}

type WrappedVaultKey struct {
	Algo       string `cbor:"algo"`        // "hkdf"
	WrappedKey []byte `cbor:"wrapped_key"` // ciphertext (+ tag)
	Nonce      []byte `cbor:"nonce"`       // 24 bytes
	KeyEpoch   uint64 `cbor:"key_epoch"`
}

type SQLitePayload struct {
	SchemaVersion uint32 `cbor:"schema_version"`
	DBBytes       []byte `cbor:"db_bytes"`
}

// EncryptPayload encrypts a decrypted payload using the Vault Key and header AAD.
func EncryptPayload(
	payload *DecryptedPayload,
	vaultKey []byte,
	headerAAD []byte,
	rng crypto.RNG,
) ([]byte, error) {

	if len(vaultKey) != crypto.XChaChaKeySize {
		return nil, fmt.Errorf("invalid vault key length")
	}

	// 1. Canonical CBOR encode inner payload
	plaintext, err := encoding.MarshalCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("payload cbor encode failed: %w", err)
	}

	// 2. Generate nonce
	nonce := make([]byte, crypto.XChaChaNonceSize)
	if _, err := rng.Read(nonce); err != nil {
		return nil, err
	}

	// 3. Encrypt
	ciphertext, err := crypto.Encrypt(
		vaultKey,
		nonce,
		plaintext,
		headerAAD,
	)
	if err != nil {
		return nil, err
	}

	// 4. Wrap in envelope
	env := EncryptedEnvelope{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	// 5. Canonical CBOR encode envelope
	return encoding.MarshalCanonical(env)
}


// DecryptPayload decrypts an encrypted envelope using the Vault Key and header AAD.
func DecryptPayload(
	envelopeBytes []byte,
	vaultKey []byte,
	headerAAD []byte,
) (*DecryptedPayload, error) {

	if len(vaultKey) != crypto.XChaChaKeySize {
		return nil, fmt.Errorf("invalid vault key length")
	}

	// 1. Decode envelope
	var env EncryptedEnvelope
	if err := encoding.UnmarshalStrict(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("envelope decode failed: %w", err)
	}

	if len(env.Nonce) != crypto.XChaChaNonceSize {
		return nil, fmt.Errorf("invalid envelope nonce length")
	}
	if len(env.Ciphertext) == 0 {
		return nil, fmt.Errorf("empty envelope ciphertext")
	}

	// 2. Decrypt
	plaintext, err := crypto.Decrypt(
		vaultKey,
		env.Nonce,
		env.Ciphertext,
		headerAAD,
	)
	if err != nil {
		// Do NOT leak whether AAD or ciphertext failed
		return nil, fmt.Errorf("payload decryption failed")
	}

	// 3. Decode inner payload
	var payload DecryptedPayload
	if err := encoding.UnmarshalStrict(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("payload decode failed: %w", err)
	}

	return &payload, nil
}
