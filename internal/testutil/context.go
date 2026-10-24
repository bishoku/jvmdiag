// Package testutil contains test-only coordination helpers. It never loads operator configuration.
package testutil

import (
	"context"
	"testing"
	"time"
)

func Context(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
