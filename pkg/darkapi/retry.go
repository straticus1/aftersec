package darkapi

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

type APIError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return fmt.Sprintf("DarkAPI returned HTTP %d", e.Status) }
func (e *APIError) Permanent() bool {
	return e.Status == 400 || e.Status == 409 || e.Status == 413 || e.Status == 422
}
func parseRetryAfter(value string, now time.Time) time.Duration {
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		delay = at.Sub(now)
	}
	if delay < 0 {
		return 0
	}
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}
func retryDelay(attempt int, hint time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 8 {
		attempt = 8
	}
	base := time.Second * time.Duration(1<<attempt)
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	delay := base/2 + time.Duration(rand.Int64N(int64(base/2)+1))
	if hint > time.Hour {
		hint = time.Hour
	}
	if hint > delay {
		return hint
	}
	return delay
}
