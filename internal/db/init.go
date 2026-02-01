package db

import (
	_ "embed"
	"database/sql"
	"fmt"
)

//go:embed schema.sql
var schemaSQL string

func Init(dbPath string) (*sql.DB, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("db path must not be empty")
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite open failed: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite ping failed: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("schema tx begin failed: %w", err)
	}

	if _, err := tx.Exec(schemaSQL); err != nil {
		tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("schema apply failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema commit failed: %w", err)
	}

	return db, nil
}

// GetMeta returns a value from the meta table.
func GetMeta(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow(
		`SELECT value FROM meta WHERE key = ?`,
		key,
	).Scan(&value)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("meta key not found: %s", key)
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetMeta sets or updates a value in the meta table.
func SetMeta(db *sql.DB, key, value string) error {
	_, err := db.Exec(
		`INSERT INTO meta (key, value)
		 VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}
