package billing

import (
	"context"
	"fmt"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/paymentmethod"
	"github.com/stripe/stripe-go/v82/subscription"
)

// PriceIDs maps tier names to Stripe price IDs.
// Override via STRIPE_PRICE_PROFESSIONAL and STRIPE_PRICE_ENTERPRISE env vars.
var PriceIDs = map[string]string{
	"professional": "price_professional_monthly",
	"enterprise":   "price_enterprise_monthly",
}

// Client wraps Stripe API calls for tier-based subscription management.
type Client struct{}

// NewClient initialises the Stripe SDK with the given secret key.
func NewClient(key string) *Client {
	stripe.Key = key
	return &Client{}
}

// EnsureCustomer returns the Stripe customer ID for the org, creating one if needed.
func (c *Client) EnsureCustomer(ctx context.Context, orgID, orgName string) (string, error) {
	searchParams := &stripe.CustomerSearchParams{
		SearchParams: stripe.SearchParams{
			Query:   fmt.Sprintf("metadata['org_id']:'%s'", orgID),
			Context: ctx,
		},
	}
	iter := customer.Search(searchParams)
	for iter.Next() {
		return iter.Customer().ID, nil
	}
	if err := iter.Err(); err != nil {
		return "", fmt.Errorf("stripe customer search: %w", err)
	}

	createParams := &stripe.CustomerParams{
		Params: stripe.Params{
			Context:  ctx,
			Metadata: map[string]string{"org_id": orgID},
		},
		Name: stripe.String(orgName),
	}
	cust, err := customer.New(createParams)
	if err != nil {
		return "", fmt.Errorf("stripe customer create: %w", err)
	}
	return cust.ID, nil
}

// Subscribe attaches the payment method to the customer and creates a subscription
// for the target tier. Any existing active subscriptions are cancelled first.
func (c *Client) Subscribe(ctx context.Context, customerID, paymentMethodID, targetTier string) (string, error) {
	priceID, ok := PriceIDs[targetTier]
	if !ok {
		return "", fmt.Errorf("no Stripe price ID configured for tier %q", targetTier)
	}

	if err := c.CancelActiveSubscriptions(ctx, customerID); err != nil {
		return "", err
	}

	// Attach payment method to customer
	_, err := paymentmethod.Attach(paymentMethodID, &stripe.PaymentMethodAttachParams{
		Params:   stripe.Params{Context: ctx},
		Customer: stripe.String(customerID),
	})
	if err != nil {
		return "", fmt.Errorf("stripe attach payment method: %w", err)
	}

	// Set as default for future invoices
	_, err = customer.Update(customerID, &stripe.CustomerParams{
		Params: stripe.Params{Context: ctx},
		InvoiceSettings: &stripe.CustomerInvoiceSettingsParams{
			DefaultPaymentMethod: stripe.String(paymentMethodID),
		},
	})
	if err != nil {
		return "", fmt.Errorf("stripe update default payment method: %w", err)
	}

	sub, err := subscription.New(&stripe.SubscriptionParams{
		Params:   stripe.Params{Context: ctx},
		Customer: stripe.String(customerID),
		Items: []*stripe.SubscriptionItemsParams{
			{Price: stripe.String(priceID)},
		},
		PaymentBehavior: stripe.String("error_if_incomplete"),
	})
	if err != nil {
		return "", fmt.Errorf("stripe subscription create: %w", err)
	}
	return sub.ID, nil
}

// CancelActiveSubscriptions cancels all active subscriptions for the customer.
func (c *Client) CancelActiveSubscriptions(ctx context.Context, customerID string) error {
	listParams := &stripe.SubscriptionListParams{
		Customer: stripe.String(customerID),
		Status:   stripe.String("active"),
	}
	listParams.Context = ctx
	iter := subscription.List(listParams)
	for iter.Next() {
		sub := iter.Subscription()
		if _, err := subscription.Cancel(sub.ID, &stripe.SubscriptionCancelParams{
			Params: stripe.Params{Context: ctx},
		}); err != nil {
			return fmt.Errorf("stripe cancel subscription %s: %w", sub.ID, err)
		}
	}
	return iter.Err()
}
