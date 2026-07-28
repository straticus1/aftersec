//go:build darwin

package netsensor

func NewPlatformBackend(eventPath, _ string) (Backend, error) {
	return NewJSONLBackend(eventPath)
}
