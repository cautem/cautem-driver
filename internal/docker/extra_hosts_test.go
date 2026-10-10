package docker

import (
	"slices"
	"testing"
)

func TestHostGatewayExtraHosts(t *testing.T) {
	got := HostGatewayExtraHosts()
	want := []string{
		"host.cautem.internal:host-gateway",
		"host.docker.internal:host-gateway",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("HostGatewayExtraHosts()=%v want %v", got, want)
	}
	if !slices.Equal(ProxyExtraHosts(), want) {
		t.Fatal("ProxyExtraHosts must match HostGatewayExtraHosts")
	}
}
