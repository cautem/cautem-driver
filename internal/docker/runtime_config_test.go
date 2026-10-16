package docker

import (
	"slices"
	"testing"
)

func TestUpstreamProxyEnvIsSidecarScopedAndCredentialFree(t *testing.T) {
	d := &Driver{runtimeConfig: RuntimeConfig{
		UpstreamProxyURL:               "https://proxy.example.test:8443",
		UpstreamProxyNoProxy:           "localhost,.svc.cluster.local",
		UpstreamProxyAuthFile:          "/tmp/auth",
		UpstreamProxyCABundle:          "/tmp/ca.pem",
		UpstreamProxyConnectByHostname: true,
	}}
	env := d.upstreamProxyEnv()
	for _, want := range []string{
		"HTTPS_PROXY=https://proxy.example.test:8443",
		"NO_PROXY=localhost,.svc.cluster.local",
		"CAUTEM_PROXY_CONNECT_BY_HOSTNAME=true",
		"CAUTEM_PROXY_AUTH_FILE=/run/cautem/upstream-proxy/auth",
		"CAUTEM_PROXY_CA_BUNDLE=/run/cautem/upstream-proxy/ca.pem",
	} {
		if !slices.Contains(env, want) {
			t.Fatalf("proxy env=%v, missing %q", env, want)
		}
	}
	for _, value := range env {
		if slices.Contains([]string{"user:pass", "https://user:pass@proxy.example.test:8443"}, value) {
			t.Fatalf("proxy secret leaked into sidecar environment: %q", value)
		}
	}
}

func TestStopTimeoutPreservesConfiguredZero(t *testing.T) {
	d := &Driver{runtimeConfig: RuntimeConfig{StopTimeoutSecs: 0, StopTimeoutConfigured: true}}
	if got := d.stopTimeoutSecs(); got != 0 {
		t.Fatalf("explicit zero stop timeout became %d seconds", got)
	}

	d = &Driver{runtimeConfig: RuntimeConfig{StopTimeoutSecs: 15, StopTimeoutConfigured: true}}
	if got := d.stopTimeoutSecs(); got != 15 {
		t.Fatalf("configured stop timeout=%d, want 15", got)
	}
}
