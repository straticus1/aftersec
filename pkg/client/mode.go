package client

type OperationMode string

const (
	ModeStandalone OperationMode = "standalone"
	ModeEnterprise OperationMode = "enterprise"
)

// IsValid checks if the given mode is supported
func (m OperationMode) IsValid() bool {
	switch m {
	case ModeStandalone, ModeEnterprise:
		return true
	}
	return false
}
