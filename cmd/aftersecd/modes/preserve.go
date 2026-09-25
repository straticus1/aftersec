package modes

import (
	"context"
	"os"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/preserve"
)

type preserveUploader struct {
	client   *client.EnterpriseClient
	tenant   string
	endpoint string
	root     string
}

func (u *preserveUploader) Preserve(ctx context.Context, incident, reason string) error {
	if u == nil || u.client == nil {
		return preserve.ErrRejected
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return preserve.ErrRejected
	}
	bundle, err := preserve.Collect(u.root, preserve.Header{IncidentID: incident, Reason: reason, Hostname: host, At: time.Now()})
	if err != nil {
		return err
	}
	body, err := preserve.Seal(incident, reason, bundle)
	if err != nil {
		return err
	}
	ok, err := u.client.SendPreserve(ctx, u.tenant, u.endpoint, string(body))
	if err != nil {
		return err
	}
	if !ok {
		return preserve.ErrRejected
	}
	return nil
}
