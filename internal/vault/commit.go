package vault

import (
	"fmt"
	"os"
	"time"
	"yap/internal/crypto"
)

/*************************************************************
Commit writes the current dirty vault state to disk atomically
On success vault transitions to CLEAN
**************************************************************/
func (v *Vault) Commit(
	outputPath string,
	rng crypto.RNG,
) error {
	// Lock the mutex to maintain atomicity
	v.mu.Lock()
	defer v.mu.Unlock()
	
	// Validtions to verify vault is healthy to be commited
	if err := v.requireState(VaultDirty); err != nil {
		return err
	}
	if v.db == nil {
		return fmt.Errorf("vault database not open")
	}

	/* 
	* Commit Steps
	* 1) Serialize SQLite db
	* 2) Update vault metadata
	* 3) Encrypt payload envelope
	* 4) Atomic write
	* 5) Transition to clean*/

	// 1) Serialize SQLite db
	dbBytes, err := os.ReadFile(v.dbPath)
	if err != nil {
		return fmt.Errorf("sqlite read failed: %w", err)
	}

	// 2) Update vault metadata
	v.vaultVersion++
	now := time.Now().Unix()
	v.header.VaultVersion = v.vaultVersion
	v.header.LastModified = now
	payload := &DecryptedPayload{
		VaultMetadata: VaultMetadata{
			VaultID: v.vaultID,
			VaultVersion: v.vaultVersion,
			KeyEpoch: v.keyEpoch,
			DeviceID: "",
			CreatedBy: "",
			LastWriter: "",
			Integrity: IntegrityBlock{
				PayloadHash: mustHash(v.dbBytes),
			},
		},
		WrappedVaultKey: v.vaultKey,
		SQLite: SQLitePayload{
			SchemaVersion: 1,
			DBBytes: dbBytes,
		},
	}

	headerAAD, err := v.header.CannonicalBytes()
	if err != nil {
		return err
	}

	encryptedPayload, err := EncryptPayload(
		payload,
		v.vaultKey.WrappedKey,
		headerAAD,
		rng,
	)
	if err != nil {
		return fmt.Errorf("payload encryption failed %w", err)
	}

	if err := atomicWriteFile(outputPath, encryptedPayload); err != nil {
		return err
	}

	v.transitionTo(VaultClean)
	v.dbBytes = dbBytes

	return nil
}

func mustHash(data []byte) []byte {
	h, err := crypto.Hash(data)
	if err != nil {
		panic("hash failure: " + err.Error())
	}
	return h
}
