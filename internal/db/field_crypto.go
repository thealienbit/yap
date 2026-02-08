package db

import (
	"fmt"
	"yap/internal/crypto"
	"yap/internal/encoding"
)

const (
	fieldEnvelopeVersion = 1
	fieldAADPrefix       = "pmgr:field"
)

type FieldEnvelope struct {
	V  uint8  `cbor:"v"`  // envelope version
	N  []byte `cbor:"n"`  // nonce 24 bytes
	CT []byte `cbor:"ct"` // ciphertext (+ poly1305 tag)
}

// AAD format - "pmgr:field" || vault_id || entry_id || column_name || envelope_version
func buildFieldAAD(
	vaultID string,
	entryID string,
	columnName string,
) ([]byte, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault_id cannot be empty")
	}
	if entryID == "" {
		return nil, fmt.Errorf("entry_id cannot be empty")
	}
	if columnName == "" {
		return nil, fmt.Errorf("column_name cannot be empty")
	}

	aad := make([]byte, 0, len(fieldAADPrefix)+len(vaultID)+len(entryID)+len(columnName)+1)
	aad = append(aad, []byte(fieldAADPrefix)...)
	aad = append(aad, []byte(vaultID)...)
	aad = append(aad, []byte(entryID)...)
	aad = append(aad, []byte(columnName)...)
	aad = append(aad, byte(fieldEnvelopeVersion))
	return aad, nil
}

func EncryptField(
	plainText []byte,
	entryKey []byte,
	vaultID string,
	entryID string,
	columnName string,
	rng crypto.RNG,
) ([]byte, error) {
	if len(entryKey) != 32 {
		return nil, fmt.Errorf("invalid entry key length")
	}

	nonce := make([]byte, crypto.XChaChaNonceSize)
	if _, err := rng.Read(nonce); err != nil {
		return nil, err
	}

	aad, err := buildFieldAAD(vaultID, entryID, columnName)
	if err != nil {
		return nil, err
	}

	ct, err := crypto.Encrypt(entryKey, nonce, plainText, aad)
	if err != nil {
		return nil, err
	}

	env := FieldEnvelope{
		V:  fieldEnvelopeVersion,
		N:  nonce,
		CT: ct,
	}
	return encoding.MarshalCanonical(env)
}

func DecryptField(
	encrypted []byte,
	entryKey []byte,
	vaultID string,
	entryID string,
	column string,
) ([]byte, error) {
	if len(entryKey) != 32 {
		return nil, fmt.Errorf("Invalid entry key length")
	}
	var env FieldEnvelope
	if err := encoding.UnmarshalStrict(encrypted, env); err != nil {
		return nil, fmt.Errorf("field decryption failed: %w", err)
	}

	// structural validations
	if env.V != fieldEnvelopeVersion {
		return nil, fmt.Errorf("invalid field envelope version")
	}

	if len(env.N) != crypto.XChaChaNonceSize {
		return nil, fmt.Errorf("invalid field nonce size")
	}

	if len(env.CT) == 0 {
		return nil, fmt.Errorf("empty field cypher text")
	}

	aad, err := buildFieldAAD(vaultID, entryID, column)
	if err != nil {
		return nil, err
	}

	plainText, err := crypto.Decrypt(entryKey, env.N, env.CT, aad)
	if err != nil {
		return nil, fmt.Errorf("field decryption failed: %w", err)
	}
	return plainText, nil
}

/*
Entry Key Column (Special Case)
The entry_key column:
Uses the same envelope
Uses Vault Key instead of Entry Key
Uses column = "entry_key"
* */
