//go:build !darwin && !linux

package response

import (
	"context"
	"fmt"
)

type unsupportedFirewall struct{}

func NewPlatformFirewall() Firewall { return unsupportedFirewall{} }
func (unsupportedFirewall) Apply(context.Context, ControlEndpoint) error {
	return fmt.Errorf("network quarantine unsupported")
}
func (unsupportedFirewall) VerifyControl(context.Context, ControlEndpoint) error {
	return fmt.Errorf("network quarantine unsupported")
}
func (unsupportedFirewall) Remove(context.Context) error {
	return fmt.Errorf("network quarantine unsupported")
}
