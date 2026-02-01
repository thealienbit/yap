package keys

import (
	"encoding/binary"
	"fmt"
	"yap/internal/crypto"
	"yap/internal/encoding"
)

const (
	VaultKeySize = 32

	wrappedVKVersion = 1
	wrapAlgo = "xchacha20-poly1305"

	hkdfWrapInfo = "pmgr:vault-key-wrap"
	aadPrefix = "pmgr:vk-wrap"
)

type WrappedVaultKey struct {
	V uint8 `cbor:"v"`
	Algo string `cbor:"algo"`
	Nonce []byte `cbor:"nonce"`
	CT []byte `cbor:"ct"`
	KeyEpoch uint64 `cbor:"key_epoch"`
}

// Derives the key encryption key from the master key
func DeriveKEK(masterKey []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length")
	}

	return crypto.HKDFExpand(
		masterKey,
		[]byte(hkdfWrapInfo),
		32,
	)
}

// AAD = "pmgr:vk-wrap" || vault_id || key_epoch
func buildWrapAAD(vaultID string, keyEpoch uint64) ([]byte, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault_id must not be empty")
	}
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, keyEpoch)

	aad := make([]byte, 0, len(aadPrefix)+len(vaultID) + 8)
	aad = append(aad, []byte(aadPrefix)...) 
	aad = append(aad, []byte(vaultID)...)
	aad = append(aad, epochBytes...)

	return aad, nil
}

// encrypts the vault key using the kek
func WrapVaultKey(
	vaultKey []byte,
	kek []byte,
	vaultID string,
	keyEpoch uint64,
	rng crypto.RNG,
) ([]byte, error) {
	if len(vaultKey) != VaultKeySize {
		return nil, fmt.Errorf("invalid vault key length")
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid KEK length")
	} 
	if keyEpoch == 0 {
		return nil, fmt.Errorf("key_epoch must be greater than 1")
	}

	nonce := make([]byte, crypto.XChaChaNonceSize)
	if _, err := rng.Read(nonce); err != nil {
		return nil, err
	}

	aad, err := buildWrapAAD(vaultID, keyEpoch)
	if err != nil {
		return nil, err
	}

	ct, err := crypto.Encrypt(
		kek,
		nonce,
		vaultKey,
		aad,
	)
	if err != nil {
		return nil, err
	}

	wrapped := WrappedVaultKey{
		V: wrappedVKVersion,
		Algo: wrapAlgo,
		Nonce: nonce,
		CT: ct,
		KeyEpoch: keyEpoch,
	}

	return encoding.MarshalCanonical(wrapped)
}

// decrypts and returns the Vault Key.
func UnwrapVaultKey(
	wrappedBytes []byte,
	kek []byte,
	vaultID string,
	expectedEpoch uint64,
) ([]byte, error) {

	if len(kek) != 32 {
		return nil, fmt.Errorf("invalid KEK length")
	}

	var wrapped WrappedVaultKey
	if err := encoding.UnmarshalStrict(wrappedBytes, &wrapped); err != nil {
		return nil, fmt.Errorf("wrapped vault key decode failed: %w", err)
	}

	// ---- Structural validation ----
	if wrapped.V != wrappedVKVersion {
		return nil, fmt.Errorf("unsupported wrapped vault key version")
	}
	if wrapped.Algo != wrapAlgo {
		return nil, fmt.Errorf("unsupported wrap algorithm")
	}
	if len(wrapped.Nonce) != crypto.XChaChaNonceSize {
		return nil, fmt.Errorf("invalid wrapped vault key nonce length")
	}
	if wrapped.KeyEpoch != expectedEpoch {
		return nil, fmt.Errorf("key_epoch mismatch")
	}

	// ---- AAD ----
	aad, err := buildWrapAAD(vaultID, wrapped.KeyEpoch)
	if err != nil {
		return nil, err
	}

	// ---- Decrypt ----
	vaultKey, err := crypto.Decrypt(
		kek,
		wrapped.Nonce,
		wrapped.CT,
		aad,
	)
	if err != nil {
		return nil, fmt.Errorf("vault key unwrap failed")
	}

	if len(vaultKey) != VaultKeySize {
		return nil, fmt.Errorf("invalid decrypted vault key length")
	}

	return vaultKey, nil
}
// re-wraps an existing Vault Key under a new KEK and increments epoch.
func RotateVaultKey(
	vaultKey []byte,
	newKEK []byte,
	vaultID string,
	oldEpoch uint64,
	rng crypto.RNG,
) (wrapped []byte, newEpoch uint64, err error) {

	if oldEpoch == 0 {
		return nil, 0, fmt.Errorf("invalid old key_epoch")
	}

	newEpoch = oldEpoch + 1

	wrapped, err = WrapVaultKey(
		vaultKey,
		newKEK,
		vaultID,
		newEpoch,
		rng,
	)
	if err != nil {
		return nil, 0, err
	}

	return wrapped, newEpoch, nil
}
