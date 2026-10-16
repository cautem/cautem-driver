//go:build !darwin && !linux

package vm

import (
	"context"
	"fmt"
)

func checkNetworkBrokerHealth(context.Context, string) error {
	return fmt.Errorf("VM policy network broker is unsupported on this platform")
}
