// Package devicecontrol enforces fail-closed removable-media decisions.
//
// Threats: unknown, spoofed, and under-identified removable devices are denied
// under block policy. It does not itself perform OS mount authorization; the
// platform adapter must apply the returned decision and report failures.
package devicecontrol

import (
	"context"
	"errors"
	"fmt"
)

type DeviceID string
type Access string
type Mode string

const (
	Deny         Access = "deny"
	ReadOnly     Access = "read-only"
	ReadWrite    Access = "read-write"
	BlockUnknown Mode   = "block-unknown"
	AllowListed  Mode   = "allow-listed"
)

var (
	ErrInvalidDevice = errors.New("invalid removable device identity")
	ErrDeviceDenied  = errors.New("removable device denied by policy")
)

type Device struct {
	ID      DeviceID
	Class   string
	Vendor  string
	Product string
	Serial  string
}

type Policy struct {
	Mode    Mode
	Allowed map[DeviceID]Access
}

type Mounter interface{ Apply(Device, Access) error }
type Source interface {
	Watch(context.Context, func(Device) error) error
}
type Recorder interface {
	RecordDeviceDecision(context.Context, Device, Access, error) error
}

type Controller struct {
	policy  Policy
	mounter Mounter
}

func NewController(policy Policy, mounter Mounter) *Controller {
	return &Controller{policy: policy, mounter: mounter}
}

func (c *Controller) Handle(device Device) error {
	if c == nil || c.mounter == nil {
		return ErrDeviceDenied
	}
	access, err := c.policy.Decide(device)
	if err != nil {
		if (errors.Is(err, ErrDeviceDenied) || errors.Is(err, ErrInvalidDevice)) &&
			device.ID != "" && len(device.ID) <= 256 {
			if applyErr := c.mounter.Apply(device, Deny); applyErr != nil {
				return fmt.Errorf("apply removable-media denial: %w", applyErr)
			}
		}
		return err
	}
	if err := c.mounter.Apply(device, access); err != nil {
		return fmt.Errorf("apply removable-media authorization: %w", err)
	}
	return nil
}

func (c *Controller) Run(ctx context.Context, source Source, recorder Recorder) error {
	if c == nil || source == nil || recorder == nil {
		return ErrDeviceDenied
	}
	return source.Watch(ctx, func(device Device) error {
		access, policyErr := c.policy.Decide(device)
		handleErr := c.Handle(device)
		if recordErr := recorder.RecordDeviceDecision(ctx, device, access, handleErr); recordErr != nil {
			return recordErr
		}
		// A successfully enforced deny is a policy outcome, not a sensor
		// failure. Enforcement or evidence failures stop the pipeline.
		if policyErr != nil &&
			(errors.Is(policyErr, ErrDeviceDenied) || errors.Is(policyErr, ErrInvalidDevice)) &&
			(handleErr == policyErr || errors.Is(handleErr, ErrDeviceDenied) || errors.Is(handleErr, ErrInvalidDevice)) {
			return nil
		}
		return handleErr
	})
}

func (p Policy) Decide(d Device) (Access, error) {
	if d.ID == "" || d.Class == "" || d.Serial == "" || len(d.ID) > 256 || len(d.Serial) > 256 {
		return Deny, ErrInvalidDevice
	}
	if d.Class != "mass-storage" {
		return Deny, fmt.Errorf("%w: unsupported device class", ErrDeviceDenied)
	}
	access, ok := p.Allowed[d.ID]
	if !ok {
		if p.Mode == BlockUnknown || p.Mode == AllowListed {
			return Deny, ErrDeviceDenied
		}
		return Deny, fmt.Errorf("%w: invalid policy mode", ErrDeviceDenied)
	}
	if access != ReadOnly && access != ReadWrite {
		return Deny, ErrDeviceDenied
	}
	return access, nil
}
