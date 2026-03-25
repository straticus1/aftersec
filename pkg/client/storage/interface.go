package storage

import (
	"aftersec/pkg/core"
)

// Manager defines the generic storage backend operations
type Manager interface {
	SaveCommit(state *core.SecurityState) error
	GetHistory() ([]*core.SecurityState, error)
	GetLatest() (*core.SecurityState, error)
	GetConfigPath() string
	LoadConfig() (*core.Config, error)
	SaveConfig(cfg *core.Config) error
}
