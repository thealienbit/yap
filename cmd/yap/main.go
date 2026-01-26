package main

import (
	"flag"
	"os"
	"yap/internal/config"
	"yap/internal/log"
)



func main() {
	// Load configs
	cfg := &config.Config{}

	flag.StringVar(&cfg.VaultPath, "vault", "", "Path to vaultfile")
	flag.StringVar(&cfg.RepoPath, "repo", "", "Path to git repository")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&cfg.ConfigFile, "config", "", "Path to config file")
	flag.Parse()

	// Initialize loggging
	log.Init(log.Dev, cfg.Debug)

	if err := config.Load(cfg); err != nil {
		log.Logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	
	log.Logger.Info("yap initialized", "vault", cfg.VaultPath)
}
