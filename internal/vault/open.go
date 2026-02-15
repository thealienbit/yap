package vault

import (
	"fmt"
	"yap/internal/crypto"
	"yap/internal/encoding"
	"yap/internal/keys"
)

// trusted local state used for rollback protection
type OpenContext struct {
	ExpectedVaultID      string
	LastSeenVaultVersion uint64
	LastSeenKeyEpoch     uint64
}

// represents an open vault
type OpenVault struct {
	Header       *VaultHeader
	Payload      *DecryptedPayload
	VaultKey     []byte
	VaultVersion uint64
	KeyEpoch     uint64
}

/* OpenVaultFile: Opens a vault file
		args - headerBytes byte[], envelopeBytes byte[], password byte[]
		returns - *OpenVault, error 
*/
func OpenVaultFile(
	headerBytes []byte,
	envelopeBytes []byte,
	password []byte,
	ctx OpenContext,
) (*OpenVault, error) {
	header, err := DecodeVaultHeader(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid vault header: %w", err)
	}
	if ctx.ExpectedVaultID != "" && header.VaultID != ctx.ExpectedVaultID {
		return nil, fmt.Errorf("vault_id mismatch with local state")
	}
	if header.VaultVersion < ctx.LastSeenVaultVersion {
		return nil, fmt.Errorf("vault_version rollback detected")
	}
	if header.KeyEpoch < ctx.LastSeenKeyEpoch {
		return nil, fmt.Errorf("key_epoch downgrade detected")
	}

	mk, err := keys.DeriveMasterKey(password, header.KDF.Salt, crypto.Argon2Params{
		Memory:      header.KDF.Memory,
		Iterations:  header.KDF.Iterations,
		Parallelism: header.KDF.Parallelism,
		KeyLength:   32,
	})
	if err != nil {
		return nil, fmt.Errorf("master key derivation failed: %w", err)
	}

	kek, err := keys.DeriveKEK(mk)
	if err != nil {
		return nil, fmt.Errorf("kek derivation failed: %w", err)
	}

	headerAAD, err := header.CannonicalBytes()
	if err != nil {
		return nil, err
	}

	payLoad, err := DecryptPayload(envelopeBytes, nil, headerAAD)
	if err == nil {
		return nil, fmt.Errorf("unexpected payload decryption without vault key")
	}

	var env EncryptedEnvelope
	if err := encoding.UnmarshalStrict(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("invalid envelope nonce")
	}

	wrappedVKBytes, err := encoding.MarshalCanonical(payLoad.WrappedVaultKey)
	if err != nil {
		return nil, fmt.Errorf("wrapped vault key encode failed: %w", err)
	}

	vaultKey, err := keys.UnwrapVaultKey(
		wrappedVKBytes,
		kek,
		header.VaultID,
		header.KeyEpoch,
	)
	if err != nil {
		return nil, fmt.Errorf("vault key unwrap failed")
	}

	payLoad, err = DecryptPayload(
		envelopeBytes, vaultKey, headerAAD,
	)
	if err != nil {
		return nil, fmt.Errorf("payload decryption failed")
	}

	if err := ValidateMetadata(header, payLoad, MetadataValidationContext{
		ExpectedVaultID:      ctx.ExpectedVaultID,
		LastSeenVaultVersion: ctx.LastSeenVaultVersion,
		LastSeenKeyEpoch:     ctx.LastSeenKeyEpoch,
	}); err != nil {
		return nil, err
	}

	return &OpenVault{
		Header:       header,
		Payload:      payLoad,
		VaultKey:     vaultKey,
		VaultVersion: header.VaultVersion,
		KeyEpoch:     header.KeyEpoch,
	}, nil
}
