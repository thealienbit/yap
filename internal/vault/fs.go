package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// atomicWriteFile writes data to path safely.
//
// Guarantees:
// - Never leaves partial file at destination
// - Survives crash after rename (POSIX)
// - Cleans up temp files on failure
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)

	// Create temp file in same directory (required for atomic rename)
	tmp, err := os.CreateTemp(dir, ".yap-tmp-*")
	if err != nil {
		return fmt.Errorf("temp file create failed: %w", err)
	}

	tmpName := tmp.Name()

	// Ensure cleanup on failure
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// Write all bytes
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("temp write failed: %w", err)
	}

	// Force file data to disk
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("file fsync failed: %w", err)
	}

	// Close before rename (important on Windows)
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("temp close failed: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}

	// POSIX requires directory fsync to guarantee rename durability
	if runtime.GOOS != "windows" {
		if err := fsyncDir(dir); err != nil {
			return fmt.Errorf("directory fsync failed: %w", err)
		}
	}

	return nil
}

func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()

	return f.Sync()
}

