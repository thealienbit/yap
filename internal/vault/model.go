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

var allowedTransitions = map[VaultState][]VaultState{
	VaultClosed:  {VaultOpening},
	VaultOpening: {VaultOpen, VaultClosed},
	VaultOpen:    {VaultDirty, VaultClean, VaultClosed},
	VaultDirty:   {VaultClean, VaultClosed},
	VaultClean:   {VaultDirty, VaultClosed},
}


type Vault struct {
	mu sync.Mutex

	state VaultState

	header   *VaultHeader
	vaultKey WrappedVaultKey

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
 
	vault := &Vault{
		state:        VaultOpening,
		header:       header,
		vaultKey:     payload.WrappedVaultKey,
		vaultID:      header.VaultID,
		vaultVersion: header.VaultVersion,
		keyEpoch:     header.KeyEpoch,
		db:           dbConn,
		dbPath:       tmpFile.Name(),
		dbBytes:      payload.SQLite.DBBytes,
	}
	if err := vault.transitionTo(VaultOpen); err != nil {
		return nil, err
	}

	return vault, nil
}

func (v *Vault) markDirty() {
	v.transitionTo(VaultDirty)
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

	if err := v.transitionTo(VaultClosed); err != nil {
		return err
	}
	return nil
}

func (v *Vault) requireState(expected VaultState) error {
	if v.state != expected {
		return fmt.Errorf(
			"vault must be %s (current: %s)",
			expected,
			v.state,
		)
	}
	return nil
}

func (v *Vault) transitionTo(next VaultState) error {
	current := v.state

	allowed := allowedTransitions[current]
	for _, s := range allowed {
		if s == next {
			v.state = next
			return nil
		}
	}

	return fmt.Errorf(
		"illegal vault state transition: %s → %s",
		current,
		next,
	)
}

