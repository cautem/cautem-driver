//go:build darwin || linux

package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateNetworkBrokerConfigRequiresPrivatePolicyAndSafeEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "cautem")
	if err := os.WriteFile(binary, []byte("proxy executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "vm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := networkBrokerConfig{
		Binary: binary, Policy: policy, Socket: filepath.Join(socketDir, "proxy.sock"),
		SSHSocket: filepath.Join(socketDir, "ssh.sock"), ControlSocket: filepath.Join(socketDir, "control.sock"),
		LogDir: filepath.Join(dir, "logs"), ProxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=secret"},
	}
	if _, err := validateNetworkBrokerConfig(config); err != nil {
		t.Fatalf("validateNetworkBrokerConfig() error = %v", err)
	}
	config.ProxyEnv = []string{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"}
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("unsafe environment error = %v", err)
	}
	config.ProxyEnv = []string{"CAUTEM_SANDBOX_TOKEN=secret"}
	environment, err := networkBrokerProcessEnvironment(config)
	if err != nil {
		t.Fatalf("networkBrokerProcessEnvironment() error = %v", err)
	}
	if !containsEnv(environment, "CAUTEM_SSH_SOCKET="+config.SSHSocket) || !containsEnv(environment, "CAUTEM_SUPERVISOR_CONTROL_SOCKET="+config.ControlSocket) {
		t.Fatalf("proxy relay socket configuration missing: %q", environment)
	}
	if containsEnv(environment, "HOME=") || containsEnv(environment, "CAUTEM_VM_CONTROL_TOKEN=") {
		t.Fatalf("host ambient environment leaked to proxy: %q", environment)
	}
	config.ProxyEnv = []string{"CAUTEM_SANDBOX_TOKEN=secret", "CAUTEM_SSH_SOCKET=/tmp/attacker.sock"}
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "cannot override") {
		t.Fatalf("proxy SSH socket override error = %v", err)
	}
	config.ProxyEnv = []string{"CAUTEM_SANDBOX_TOKEN=secret"}
	config.Socket = filepath.Join(socketDir, strings.Repeat("x", 100)+".sock")
	if _, err := validateNetworkBrokerConfig(config); err == nil || !strings.Contains(err.Error(), "socket path limit") {
		t.Fatalf("long socket path error = %v", err)
	}
}

func TestValidateWorkerNetworkBrokerRequiresGuestInitiatedMapping(t *testing.T) {
	config := workerConfig{
		NetworkBroker: &networkBrokerConfig{Socket: "/tmp/broker.sock"},
		Launch: KrunLaunchConfig{
			VsockPorts: []KrunVsockPort{{Port: networkBrokerVsockPort, Socket: "/tmp/broker.sock", Listen: false}},
			Env:        []string{"CAUTEM_VM_NETWORK_BROKER_PORT=5501", "CAUTEM_VM_NETWORK_PROXY_PORT=3128"},
		},
	}
	if err := validateWorkerNetworkBroker(config); err != nil {
		t.Fatalf("valid network broker config rejected: %v", err)
	}
	config.Launch.VsockPorts = append(config.Launch.VsockPorts, KrunVsockPort{Port: 5504, Socket: "/tmp/unexpected.sock"})
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "unrecognized vsock port mapping 5504") {
		t.Fatalf("unexpected guest-to-host vsock mapping error = %v", err)
	}
	config.Launch.VsockPorts = config.Launch.VsockPorts[:1]
	config.Launch.VsockPorts[0].Listen = true
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "guest-initiated") {
		t.Fatalf("host-listening broker mapping error = %v", err)
	}
	config.Launch.VsockPorts[0].Listen = false
	config.Launch.Env = []string{"CAUTEM_VM_NETWORK_BROKER_PORT=5501"}
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "guest proxy port") {
		t.Fatalf("missing proxy port error = %v", err)
	}
}

func TestValidateWorkerRelayMappingsRequireExpectedVsockDirection(t *testing.T) {
	config := workerConfig{
		NetworkBroker: &networkBrokerConfig{
			Socket: "/tmp/cautem-vm/proxy.sock", SSHSocket: "/tmp/cautem-vm/ssh.sock",
			ControlSocket: "/tmp/cautem-vm/control.sock",
		},
		Launch: KrunLaunchConfig{
			VsockPorts: []KrunVsockPort{
				{Port: networkBrokerVsockPort, Socket: "/tmp/cautem-vm/proxy.sock", Listen: false},
				{Port: sshRelayVsockPort, Socket: "/tmp/cautem-vm/ssh.sock", Listen: true},
				{Port: supervisorControlPort, Socket: "/tmp/cautem-vm/control.sock", Listen: false},
			},
			Env: []string{
				"CAUTEM_VM_NETWORK_BROKER_PORT=5501", "CAUTEM_VM_NETWORK_PROXY_PORT=3128",
				"CAUTEM_VM_SSH_RELAY_PORT=5502", "CAUTEM_VM_SUPERVISOR_CONTROL_PORT=5503",
				"CAUTEM_VM_SUPERVISOR_ENABLED=1",
			},
		},
	}
	if err := validateWorkerNetworkBroker(config); err != nil {
		t.Fatalf("complete SSH and supervisor relay mappings rejected: %v", err)
	}
	config.Launch.VsockPorts[1].Listen = false
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "host-listening SSH relay") {
		t.Fatalf("guest-initiated SSH mapping error = %v", err)
	}
	config.Launch.VsockPorts[1].Listen = true
	config.Launch.VsockPorts[2].Listen = true
	if err := validateWorkerNetworkBroker(config); err == nil || !strings.Contains(err.Error(), "guest-initiated supervisor control") {
		t.Fatalf("host-listening control mapping error = %v", err)
	}
}

func TestNetworkBrokerEnvironmentDoesNotInheritHostSecretsOrLoaderOverrides(t *testing.T) {
	env := networkBrokerEnvironment([]string{"TOKEN_GRANTS={}", "CAUTEM_SANDBOX_TOKEN=secret"})
	if len(env) != 3 || env[0] != "CAUTEM_SANDBOX_TOKEN=secret" || env[1] != "PATH=/usr/bin:/bin" || env[2] != "TOKEN_GRANTS={}" {
		t.Fatalf("network broker environment = %q", env)
	}
}

func containsEnv(environment []string, expected string) bool {
	for _, entry := range environment {
		if entry == expected {
			return true
		}
	}
	return false
}
