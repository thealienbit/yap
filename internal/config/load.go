package config

import (
	"fmt"
	"os"
)


func Load(cfg *Config) error {
	if cfg.ConfigFile != "" {
		info, err := os.Stat(cfg.ConfigFile)
		if err != nil {
			return fmt.Errorf("config file error: %w", err)
		}

		// Enforce 0600 permissions
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf(
				"config file %s must not be group/world readable",
				cfg.ConfigFile,
			)
		}

		// Parsing logic 
	}

	if cfg.VaultPath == "" {
		return fmt.Errorf("vault path is required")
	}

	return nil
}
