package main

import (
	"log"
	"path/filepath"

	"aftersec/pkg/client"
	"aftersec/pkg/writeflags"
)

func loadWriteFlags(cfg *client.ClientConfig) *writeflags.Set {
	if cfg == nil || !cfg.Daemon.WriteFlags.Enabled {
		set, err := writeflags.Load(nil)
		if err != nil {
			log.Fatalf("write flags: %v", err)
		}
		return set
	}
	specs := make([]writeflags.Spec, 0, len(cfg.Daemon.WriteFlags.Flags))
	for _, flag := range cfg.Daemon.WriteFlags.Flags {
		specs = append(specs, writeflags.Spec{Path: flag.Path, Mode: flag.Mode, AllowUIDs: flag.AllowUIDs})
	}
	set, err := writeflags.Load(specs)
	if err != nil {
		log.Fatalf("write flags: %v", err)
	}
	log.Printf("write flags active: %d", len(cfg.Daemon.WriteFlags.Flags))
	return set
}

func writeFlagDecision(set *writeflags.Set, path string, uid uint32) writeflags.Decision {
	paths := []string{path}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		paths = append(paths, resolved)
	}
	return set.Apply(paths, uid)
}
