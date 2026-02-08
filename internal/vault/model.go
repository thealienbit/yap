package vault

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"yap/internal/db"
)

type VaultState int

const (
	VaultClosed VaultState = iota
	VaultOpening
	VaultOpen
	VaultDirty
	VaultClean
)

type Vault struct {
	mu sync.Mutex

	state VaultState

	header   *VaultHeader
	vaultKey []byte

	vaultID      string
	vaultVersion uint64
	keyEpoch     uint64

	db      *sql.DB
	dbPath  string
	dbBytes []byte // decrypted SQLite bytes
}

func (v *Vault) ensureState(expected VaultState) (error) {
	if (v.state != expected) {
		return  fmt.Errorf("invalid vault state: %v", v.state)
	}
	return nil
}

func newOpenVault(
	header *VaultHeader,
	payload *DecryptedPayload,
	vaultKey []byte,
) (*Vault, error) {
	tmpFile, err := os.CreateTemp("", "yap-vault-*.db")
	if err != nil {
		return nil, err
	}

	if _, err := tmpFile.Write(payload.SQLite.DBBytes); err != nil {
		return nil, err
	}
	tmpFile.Close()

	dbConn, err := db.Init(tmpFile.Name())
	if err != nil {
		return nil, err
	}

	return &Vault{
		state:        VaultOpen,
		header:       header,
		vaultKey:     vaultKey,
		vaultID:      header.VaultID,
		vaultVersion: header.VaultVersion,
		keyEpoch:     header.KeyEpoch,
		db:           dbConn,
		dbPath:       tmpFile.Name(),
		dbBytes:      payload.SQLite.DBBytes,
	}, nil
}

func (v *Vault) markDirty() {
	if v.state == VaultOpen || v.state == VaultClean {
		v.state = VaultDirty
	}
}

func (v *Vault) CanCommit() bool {
	return v.state == VaultDirty
}

func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.db != nil {
		v.db.Close()
	}
	if v.dbPath != "" {
		os.Remove(v.dbPath)
	}

	v.state = VaultClosed
	return nil
}

