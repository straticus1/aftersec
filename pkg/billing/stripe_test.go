package billing

import (
	"context"
	"strings"
	"testing"

	"github.com/stripe/stripe-go/v82"
)

func TestNewClient_SetsStripeKey(t *testing.T) {
	const key = "sk_test_testkey_abc123"
	NewClient(key)
	if stripe.Key != key {
		t.Errorf("expected stripe.Key = %q, got %q", key, stripe.Key)
	}
}

func TestPriceIDs_DefaultsExist(t *testing.T) {
	if _, ok := PriceIDs["professional"]; !ok {
		t.Error("PriceIDs missing 'professional'")
	}
	if _, ok := PriceIDs["enterprise"]; !ok {
		t.Error("PriceIDs missing 'enterprise'")
	}
}

func TestSubscribe_UnknownTier(t *testing.T) {
	c := NewClient("sk_test_key")
	_, err := c.Subscribe(context.Background(), "cus_123", "pm_123", "unknown_tier")
	if err == nil {
		t.Fatal("expected error for unknown tier, got nil")
	}
	if !strings.Contains(err.Error(), "unknown_tier") {
		t.Errorf("error should mention tier name, got: %v", err)
	}
}

func TestSubscribe_UnknownTier_AllTiers(t *testing.T) {
	c := NewClient("sk_test_key")
	for _, tier := range []string{"free", "basic", "starter", ""} {
		_, err := c.Subscribe(context.Background(), "cus_123", "pm_123", tier)
		if err == nil {
			t.Errorf("tier %q: expected error, got nil", tier)
		}
	}
}
