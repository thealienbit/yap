package db

import (
	"database/sql"
	"fmt"
	"time"
	"yap/internal/crypto"
	"yap/internal/keys"
)

type Entry struct {
	ID        string
	Title     string
	Username  string
	Password  string
	URL       string
	Notes     string
	CreatedAt int64
	UpdatedAt int64
}

func CreateEntry(
	db *sql.DB,
	vaultID string,
	vaultKey []byte,
	entry Entry,
	rng crypto.RNG,
) error {
	if entry.ID == "" {
		return fmt.Errorf("entry id required")
	}

	now := time.Now().Unix()
	entry.CreatedAt = now
	entry.UpdatedAt = now

	entryKey, err := keys.GenerateEntryKey(rng)
	if err != nil {
		return fmt.Errorf("entry key generation failed: %w", err)
	}
	// encrypt entry key
	encEntryKey, err := EncryptField(entryKey, vaultKey, vaultID, entry.ID, "entry_key", rng)
	if err != nil {
		return err
	}

	// encrypt fields
	title, err := EncryptField([]byte(entry.Title), entryKey, vaultID, entry.ID, "title", rng)
	if err != nil {
		return err
	}
	username, err := EncryptField([]byte(entry.Username), entryKey, vaultID, entry.ID, "username", rng)
	if err != nil {
		return err
	}
	password, err := EncryptField([]byte(entry.Password), entryKey, vaultID, entry.ID, "password", rng)
	if err != nil {
		return err
	}
	url, err := EncryptField([]byte(entry.URL), entryKey, vaultID, entry.ID, "url", rng)
	if err != nil {
		return err
	}
	notes, err := EncryptField([]byte(entry.Notes), entryKey, vaultID, entry.ID, "notes", rng)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		INSERT INTO entries (
			id, title, username, password, url, notes,
			created_at, updated_at, entry_key
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		title,
		username,
		password,
		url,
		notes,
		entry.CreatedAt,
		entry.UpdatedAt,
		encEntryKey,
	)

	return err
}

func GetEntry(
	db *sql.DB,
	vaultID string,
	vaultKey []byte,
	entryID string,
) (*Entry, error) {

	row := db.QueryRow(`
		SELECT title, username, password, url, notes,
		       created_at, updated_at, entry_key
		FROM entries WHERE id = ?`,
		entryID,
	)

	var (
		titleEnc, usernameEnc, passwordEnc, urlEnc, notesEnc []byte
		entryKeyEnc                                           []byte
		createdAt, updatedAt                                  int64
	)

	if err := row.Scan(
		&titleEnc,
		&usernameEnc,
		&passwordEnc,
		&urlEnc,
		&notesEnc,
		&createdAt,
		&updatedAt,
		&entryKeyEnc,
	); err != nil {
		return nil, err
	}

	// 1. Decrypt Entry Key
	entryKey, err := DecryptField(
		entryKeyEnc,
		vaultKey,
		vaultID,
		entryID,
		"entry_key",
	)
	if err != nil {
		return nil, err
	}

	// 2. Decrypt fields
	title, err := DecryptField(titleEnc, entryKey, vaultID, entryID, "title")
	if err != nil {
		return nil, err
	}
	username, err := DecryptField(usernameEnc, entryKey, vaultID, entryID, "username")
	if err != nil {
		return nil, err
	}
	password, err := DecryptField(passwordEnc, entryKey, vaultID, entryID, "password")
	if err != nil {
		return nil, err
	}
	url, err := DecryptField(urlEnc, entryKey, vaultID, entryID, "url")
	if err != nil {
		return nil, err
	}
	notes, err := DecryptField(notesEnc, entryKey, vaultID, entryID, "notes")
	if err != nil {
		return nil, err
	}

	return &Entry{
		ID:        entryID,
		Title:     string(title),
		Username:  string(username),
		Password:  string(password),
		URL:       string(url),
		Notes:     string(notes),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

func UpdateEntry(
	db *sql.DB,
	vaultID string,
	vaultKey []byte,
	entry Entry,
	rng crypto.RNG,
) error {

	now := time.Now().Unix()
	entry.UpdatedAt = now

	// Load encrypted entry key
	var entryKeyEnc []byte
	if err := db.QueryRow(
		`SELECT entry_key FROM entries WHERE id = ?`,
		entry.ID,
	).Scan(&entryKeyEnc); err != nil {
		return err
	}

	entryKey, err := DecryptField(
		entryKeyEnc,
		vaultKey,
		vaultID,
		entry.ID,
		"entry_key",
	)
	if err != nil {
		return err
	}

	// Encrypt updated fields
	title, err := EncryptField([]byte(entry.Title), entryKey, vaultID, entry.ID, "title", rng)
	if err != nil {
		return err
	}
	username, err := EncryptField([]byte(entry.Username), entryKey, vaultID, entry.ID, "username", rng)
	if err != nil {
		return err
	}
	password, err := EncryptField([]byte(entry.Password), entryKey, vaultID, entry.ID, "password", rng)
	if err != nil {
		return err
	}
	url, err := EncryptField([]byte(entry.URL), entryKey, vaultID, entry.ID, "url", rng)
	if err != nil {
		return err
	}
	notes, err := EncryptField([]byte(entry.Notes), entryKey, vaultID, entry.ID, "notes", rng)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE entries SET
			title = ?, username = ?, password = ?, url = ?, notes = ?,
			updated_at = ?
		WHERE id = ?`,
		title,
		username,
		password,
		url,
		notes,
		entry.UpdatedAt,
		entry.ID,
	)

	return err
}

func DeleteEntry(db *sql.DB, entryID string) error {
	_, err := db.Exec(`DELETE FROM entries WHERE id = ?`, entryID)
	return err
}

func ListEntryIDs(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM entries ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
