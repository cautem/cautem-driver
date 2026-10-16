package e2e

import (
	"testing"

	"github.com/cautem/quarshell-driver/tests/internal/testenv"
)

func TestTestcontainersRuntime(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	testenv.RunAlpine(ctx, t)
}
