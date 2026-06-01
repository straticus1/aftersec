//go:build linux

package edr

import "errors"

type ESConsumer struct{}

func NewESConsumer(_ chan<- ProcessEvent) (*ESConsumer, error) {
	return nil, errors.New("Endpoint Security not available on Linux")
}

func (c *ESConsumer) Subscribe(_ []uint32) error {
	return errors.New("Endpoint Security not available on Linux")
}

func (c *ESConsumer) RespondAuth(_ ProcessEvent, _, _ bool) error {
	return errors.New("Endpoint Security not available on Linux")
}
