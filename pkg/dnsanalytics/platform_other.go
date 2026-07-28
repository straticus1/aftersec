//go:build !darwin && !linux

package dnsanalytics

import "fmt"

func NewPlatformSource(_, _ string) (Source, error) {
	return nil, fmt.Errorf("native DNS capture is unsupported on this platform")
}
