package detection

import (
	"encoding/base64"
	"strings"
	"time"
)

const HeartbeatPrefix = "RUN_SIGMA_PACK::"

func HeartbeatAction(signed SignedPack) (string, error) {
	raw, err := MarshalPack(signed)
	if err != nil {
		return "", err
	}
	return HeartbeatPrefix + base64.StdEncoding.EncodeToString(raw), nil
}

func ActivateHeartbeatAction(action string, store *Store, now time.Time) ([]Rule, error) {
	if store == nil || !strings.HasPrefix(action, HeartbeatPrefix) {
		return nil, ErrInvalidPack
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(action, HeartbeatPrefix))
	if err != nil {
		return nil, ErrInvalidPack
	}
	signed, err := UnmarshalPack(raw)
	if err != nil {
		return nil, err
	}
	if err := store.Activate(signed, now); err != nil {
		return nil, err
	}
	return signed.Pack.Rules, nil
}
