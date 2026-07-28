//go:build darwin

package dnsanalytics

func NewPlatformSource(eventPath, _ string) (Source, error) {
	return NewJSONLSource(eventPath)
}
