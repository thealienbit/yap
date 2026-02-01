/*
* This file handles
* - entry key generation
* - secure storage format
* - encryption decryption using the vault key
* - context-binding via aad
* */
package keys

import (
	"fmt"
	"yap/internal/crypto"
	"yap/internal/encoding"
)

const (
	EntryKeySize = 32
	entryKeyVersion = 1
	entryKeyAlgo = "xchacha20-poly1305"
	entryAADPrefix = "pmgr:entry-key"
)

// SQLite entry_key column
type EncryptedEntryKey struct {
	V     uint8  `cbor:"v"`
	Algo  string `cbor:"algo"`
	Nonce []byte `cbor:"nonce"` // 24 bytes
	CT    []byte `cbor:"ct"`    // ciphertext + tag
}

// Generates a new random entry key
func GenerateEntryKey(rng crypto.RNG) ([]byte, error) {
	key := make([]byte, EntryKeySize)
	if _, err := rng.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}


// AAD construction
func buildEntryKeyAAD(vaultID string, entryID string) ([]byte, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault_id cannot be empty")
	}
	if entryID == "" {
		return nil, fmt.Errorf("entry_id cannot be empty")
	}

	aad := make([]byte, 0, len(entryAADPrefix) + len(vaultID) + len(entryID))
	aad = append(aad, []byte(entryAADPrefix)...)
	aad = append(aad, []byte(vaultID)...)
	aad = append(aad, []byte(entryID)...)

	return aad, nil
}

// Encrypt Entry Key 
func EncryptEntryKey(
	entryKey []byte,
	vaultKey []byte,
	vaultID string,
	entryID string,
	rng crypto.RNG,
) ([]byte, error) {
	// validations
	if len(entryKey) != EntryKeySize {
		return nil, fmt.Errorf("invalid entry key length")
	}
	if len(vaultKey) != VaultKeySize {
		return nil, fmt.Errorf("invalid vaukt key length")
	}
	
	nonce := make([]byte, crypto.XChaChaNonceSize)
	if _, err := rng.Read(nonce); err != nil {
		return nil, err
	}

	aad, err := buildEntryKeyAAD(vaultID, entryID) 
	if err != nil {
		return nil, err
	}

	ct, err := crypto.Encrypt(
		vaultKey,
		nonce,
		entryKey,
		aad,
	)
	if err != nil {
		return nil, err
	}


	env := EncryptedEntryKey{
		V: entryKeyVersion,
		Algo: entryKeyAlgo,
		Nonce: nonce,
		CT: ct,
	}

	return encoding.MarshalCanonical(env)
}

// Decrypt entry key using the vault key
func DecryptEntryKey(
	encrypted []byte,
	vaultKey []byte,
	vaultID string,
	entryID string,
) ([]byte, error) {
	if (len(vaultKey) != VaultKeySize) {
		return nil, fmt.Errorf("invalid vault key length")
	}
	
	var env EncryptedEntryKey
	if err := encoding.UnmarshalStrict(encrypted, &env); err != nil {
		return nil, fmt.Errorf("entry key decode failed: %s", err)
	}


	if env.V != entryKeyVersion {
		return nil, fmt.Errorf("unsupported entry key version")
	}
	if env.Algo != entryKeyAlgo {
		return nil, fmt.Errorf("unsupported entry key algo")
	}
	if len(env.Nonce) != crypto.XChaChaNonceSize {
		return nil, fmt.Errorf("invalid entry key nonce length")
	}

	aad, err := buildEntryKeyAAD(vaultID, entryID)
	if err != nil {
		return nil, err
	}

	entryKey, err := crypto.Decrypt(
		vaultKey,
		env.Nonce,
		env.CT,
		aad,
	)
	if err != nil {
		return nil, fmt.Errorf("entry key decryption failed")
	}

	if len(entryKey) != EntryKeySize {
		return nil, fmt.Errorf("invalid decrypted entry key length")
	}
	return entryKey, nil
}

