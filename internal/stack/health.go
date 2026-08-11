package stack

import (
	"context"
	"fmt"
	"time"

	"github.com/preved911/opencode-sandbox/internal/firewall"
)

// WaitForHealthy waits for the firewall container to become healthy.
// It polls the health check at intervals until the timeout is reached.
func WaitForHealthy(ctx context.Context, fw *firewall.FirewallContainer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 500 * time.Millisecond

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %s waiting for firewall health", timeout)
		}

		if err := fw.HealthCheck(ctx); err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			// Continue polling
		}
	}
}
