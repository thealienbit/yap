package vault

import (
	"fmt"

	"yap/internal/crypto"
)


/*
* Validation order
* 1) Decode + validate header
* 2) Derive keys
* 3) Decrypt payload
* 4) Decrypt payload CBOR
* 5) Validate Metadata
* 6) Then 
* 		- trust sqlite bytes
* 		- Load db 
* 		- Update local state
* */

// MetadataValidationContext represents trusted local state
// This is NOT stored inside the vault

type MetadataValidationContext struct {
	ExpectedVaultID string
	LastSeenVaultVersion uint64
	LastSeenKeyEpoch uint64
}

// ValidateMetadata validates decrypted vault metadata against header and local state.
// This function MUST be called before trusting any decrypted payload.
func ValidateMetadata(
	header *VaultHeader,
	payload *DecryptedPayload,
	ctx MetadataValidationContext,
) error {

	meta := payload.VaultMetadata

	// ---- Vault identity ----
	if meta.VaultID != header.VaultID {
		return fmt.Errorf("vault_id mismatch between header and payload")
	}

	if ctx.ExpectedVaultID != "" && meta.VaultID != ctx.ExpectedVaultID {
		return fmt.Errorf("vault_id does not match expected vault")
	}

	// ---- Vault version (rollback protection) ----
	if meta.VaultVersion != header.VaultVersion {
		return fmt.Errorf("vault_version mismatch between header and payload")
	}

	if meta.VaultVersion < ctx.LastSeenVaultVersion {
		return fmt.Errorf("vault_version rollback detected")
	}

	// ---- Key epoch (crypto downgrade protection) ----
	if meta.KeyEpoch != header.KeyEpoch {
		return fmt.Errorf("key_epoch mismatch between header and payload")
	}

	if meta.KeyEpoch < ctx.LastSeenKeyEpoch {
		return fmt.Errorf("key_epoch downgrade detected")
	}

	// ---- Device metadata sanity ----
	if meta.DeviceID == "" {
		return fmt.Errorf("device_id must not be empty")
	}
	if meta.CreatedBy == "" {
		return fmt.Errorf("created_by must not be empty")
	}
	if meta.LastWriter == "" {
		return fmt.Errorf("last_writer must not be empty")
	}

	// ---- Integrity hash ----
	if err := validatePayloadHash(payload); err != nil {
		return err
	}

	return nil
}

func validatePayloadHash(payload *DecryptedPayload) error {
	expected := payload.VaultMetadata.Integrity.PayloadHash
	if len(expected) == 0 {
		return fmt.Errorf("missing payload integrity hash")
	}

	dbBytes := payload.SQLite.DBBytes
	if len(dbBytes) == 0 {
		return fmt.Errorf("empty sqlite payload")
	}

	actual, err := crypto.Hash(dbBytes)
	if err != nil {
		return fmt.Errorf("payload hash computation failed: %w", err)
	}

	if !equalBytes(actual, expected) {
		return fmt.Errorf("payload integrity hash mismatch")
	}

	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

