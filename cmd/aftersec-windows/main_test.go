package main

import (
	"context"
	"errors"
	"testing"
)

func TestScanFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		output string
		err    error
		passed bool
	}{
		{"true", nil, true}, {"false", nil, false}, {"null", nil, false}, {"", nil, false}, {"true garbage", nil, false}, {"true", errors.New("access denied"), false},
	} {
		results := scan(context.Background(), func(context.Context, string) ([]byte, error) { return []byte(tc.output), tc.err })
		if len(results) != 2 {
			t.Fatal(results)
		}
		for _, r := range results {
			if r.Passed != tc.passed {
				t.Fatalf("%+v: %+v", tc, r)
			}
		}
	}
}

func TestScanHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, r := range scan(ctx, func(context.Context, string) ([]byte, error) { return []byte("true"), nil }) {
		if r.Passed || r.Error == "" {
			t.Fatal(r)
		}
	}
}
