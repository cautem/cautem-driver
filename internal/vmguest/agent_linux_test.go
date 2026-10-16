//go:build linux

package vmguest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuestControlRequiresPerSandboxToken(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if server.authorized("") || server.authorized(server.token[:62]+"00") || !server.authorized(server.token) {
		t.Fatal("guest control token authorization did not reject invalid credentials")
	}
	guest, host := net.Pipe()
	defer guest.Close()
	go server.serve(guest)
	if err := WriteFrame(host, []byte(`{"version":1,"operation":"shutdown"}`)); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(host)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(frame, &response); err != nil {
		t.Fatal(err)
	}
	_ = host.Close()
	if response.Error != "unauthorized guest control request" {
		t.Fatalf("unauthenticated shutdown response=%+v", response)
	}
	if response.Version != ProtocolVersion {
		t.Fatalf("response version=%d; want %d", response.Version, ProtocolVersion)
	}
}

func TestGuestControlRotatesTokenAndAllowsOnlyIdempotentRetry(t *testing.T) {
	oldToken := strings.Repeat("1", 64)
	nextToken := strings.Repeat("2", 64)
	rotationID := strings.Repeat("a", 32)
	server := &controlServer{token: oldToken}
	call := func(request Request) Response {
		t.Helper()
		guest, host := net.Pipe()
		defer guest.Close()
		go server.serve(guest)
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(host, encoded); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(host)
		if err != nil {
			t.Fatal(err)
		}
		_ = host.Close()
		var response Response
		if err := json.Unmarshal(frame, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	rotation := Request{
		Version: ProtocolVersion, AuthToken: oldToken, NextAuthToken: nextToken,
		RotationID: rotationID, Operation: "rotate-token",
	}
	if response := call(rotation); response.Error != "" {
		t.Fatalf("rotate token response=%+v", response)
	}
	if !server.authorized(nextToken) || server.authorized(oldToken) {
		t.Fatal("guest did not replace the old control token")
	}
	if response := call(rotation); response.Error != "" {
		t.Fatalf("idempotent rotation retry response=%+v", response)
	}
	rotation.RotationID = strings.Repeat("b", 32)
	if response := call(rotation); response.Error != "unauthorized guest control request" {
		t.Fatalf("altered rotation retry response=%+v", response)
	}
	if response := call(Request{Version: ProtocolVersion, AuthToken: oldToken, Operation: "ping"}); response.Error != "unauthorized guest control request" {
		t.Fatalf("old token ping response=%+v", response)
	}
}

func TestGuestControlRejectsUnsupportedProtocolVersions(t *testing.T) {
	server := &controlServer{token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	for _, version := range []uint16{0, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			guest, host := net.Pipe()
			defer guest.Close()
			go server.serve(guest)
			encoded, err := json.Marshal(Request{Version: version, AuthToken: server.token, Operation: "ping"})
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFrame(host, encoded); err != nil {
				t.Fatal(err)
			}
			frame, err := ReadFrame(host)
			if err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.Unmarshal(frame, &response); err != nil {
				t.Fatal(err)
			}
			_ = host.Close()
			if response.Error == "" || response.Version != ProtocolVersion {
				t.Fatalf("unsupported version response=%+v", response)
			}
		})
	}
}

func TestGuestWorkloadEnvironmentDoesNotInheritAgentSecrets(t *testing.T) {
	t.Setenv("CAUTEM_VM_CONTROL_TOKEN", "must-not-leak")
	for _, entry := range guestEnvironment(nil) {
		if entry == "CAUTEM_VM_CONTROL_TOKEN=must-not-leak" {
			t.Fatal("guest workload inherited the agent control token")
		}
	}
}

func TestGuestWorkloadEnvironmentForcesPolicyBrokerAndDropsControlValues(t *testing.T) {
	env := guestEnvironmentForWorkload([]string{
		"HTTP_PROXY=http://attacker.invalid:8080",
		"https_proxy=http://attacker.invalid:8080",
		"NO_PROXY=example.com",
		"CAUTEM_VM_NETWORK_BROKER_PORT=9999",
		"OPENSHELL_OCI_IMAGE_USER=spoofed",
		"OPENSHELL_SANDBOX_UID=0",
		"OPENSHELL_SANDBOX_GID=0",
		"TOKEN=guest-value",
	}, "http://127.0.0.1:3128")
	values := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if values[key] != "http://127.0.0.1:3128" {
			t.Errorf("%s=%q; want forced guest policy proxy", key, values[key])
		}
	}
	if values["NO_PROXY"] != "localhost,127.0.0.1,::1" || values["no_proxy"] != values["NO_PROXY"] {
		t.Errorf("no_proxy values = %q / %q", values["NO_PROXY"], values["no_proxy"])
	}
	for _, key := range []string{
		"CAUTEM_VM_NETWORK_BROKER_PORT", "OPENSHELL_OCI_IMAGE_USER",
		"OPENSHELL_SANDBOX_UID", "OPENSHELL_SANDBOX_GID",
	} {
		if _, ok := values[key]; ok {
			t.Fatalf("internal identity/control value %s leaked to workload", key)
		}
	}
	if values["TOKEN"] != "guest-value" {
		t.Fatalf("unrelated workload env was dropped: %v", values)
	}
}

func TestGuestWorkloadCredentialAppliesOCIUserFailClosed(t *testing.T) {
	defaultCredential, err := guestWorkloadCredential("", 1000, 1001)
	if err != nil || defaultCredential.Uid != 1000 || defaultCredential.Gid != 1001 {
		t.Fatalf("default credential = %+v, %v", defaultCredential, err)
	}
	credential, err := guestWorkloadCredential("1234:1235", 1000, 1001)
	if err != nil || credential.Uid != 1234 || credential.Gid != 1235 {
		t.Fatalf("numeric OCI credential = %+v, %v", credential, err)
	}
	for _, declaration := range []string{"0", "0:1000", "1000:0", "1000:1000:1000", "unknown-user-name-for-test"} {
		if _, err := guestWorkloadCredential(declaration, 1000, 1001); err == nil {
			t.Errorf("guestWorkloadCredential(%q) unexpectedly succeeded", declaration)
		}
	}
}

func TestNetworkProxyConfigurationRequiresValidPortPair(t *testing.T) {
	t.Setenv("CAUTEM_VM_NETWORK_PROXY_PORT", "3128")
	t.Setenv("CAUTEM_VM_NETWORK_BROKER_PORT", "5501")
	proxyPort, brokerPort, err := networkProxyConfigurationFromEnvironment()
	if err != nil || proxyPort != 3128 || brokerPort != 5501 {
		t.Fatalf("networkProxyConfigurationFromEnvironment() = (%d, %d, %v)", proxyPort, brokerPort, err)
	}
	if os.Getenv("CAUTEM_VM_NETWORK_PROXY_PORT") != "" || os.Getenv("CAUTEM_VM_NETWORK_BROKER_PORT") != "" {
		t.Fatal("internal network proxy configuration was not removed from guest agent environment")
	}
	t.Setenv("CAUTEM_VM_NETWORK_PROXY_PORT", "3128")
	t.Setenv("CAUTEM_VM_NETWORK_BROKER_PORT", "")
	if _, _, err := networkProxyConfigurationFromEnvironment(); err == nil {
		t.Fatal("partial network proxy configuration was accepted")
	}
}

func TestGuestRelayConfigurationValidatesPortsAndSupervisorPair(t *testing.T) {
	t.Setenv("CAUTEM_VM_SSH_RELAY_PORT", "5502")
	t.Setenv("CAUTEM_VM_SUPERVISOR_CONTROL_PORT", "5503")
	t.Setenv("CAUTEM_VM_SUPERVISOR_ENABLED", "1")
	config, err := relayConfigurationFromEnvironment()
	if err != nil || config.sshPort != 5502 || config.controlPort != 5503 || !config.supervisor {
		t.Fatalf("relayConfigurationFromEnvironment() = %+v, %v", config, err)
	}
	for _, key := range []string{"CAUTEM_VM_SSH_RELAY_PORT", "CAUTEM_VM_SUPERVISOR_CONTROL_PORT", "CAUTEM_VM_SUPERVISOR_ENABLED"} {
		if os.Getenv(key) != "" {
			t.Errorf("internal VM relay setting %s was not removed", key)
		}
	}
	t.Setenv("CAUTEM_VM_SUPERVISOR_CONTROL_PORT", "5503")
	t.Setenv("CAUTEM_VM_SUPERVISOR_ENABLED", "")
	if _, err := relayConfigurationFromEnvironment(); err == nil || !strings.Contains(err.Error(), "must be configured together") {
		t.Fatalf("orphaned supervisor control bridge error = %v", err)
	}
}

func TestGuestWorkloadAndExecCommandsUseHardenedSupervisorPattern(t *testing.T) {
	workload := guestWorkloadCommand([]string{"/bin/sh", "-c", "printf a b"}, true)
	wantWorkload := []string{
		guestSupervisorBinary, "--", guestInitBinary, "--policy", guestPolicyFile, "--",
		"/bin/sh", "-c", "printf a b",
	}
	if strings.Join(workload, "\x00") != strings.Join(wantWorkload, "\x00") {
		t.Fatalf("supervised workload argv = %q; want %q", workload, wantWorkload)
	}
	execArgv := guestExecCommand([]string{"/usr/bin/id", "-u"}, true)
	wantExec := []string{guestInitBinary, "--policy", guestPolicyFile, "--", "/usr/bin/id", "-u"}
	if strings.Join(execArgv, "\x00") != strings.Join(wantExec, "\x00") {
		t.Fatalf("hardened exec argv = %q; want %q", execArgv, wantExec)
	}
	if got := guestWorkloadCommand([]string{"true"}, false); len(got) != 1 || got[0] != "true" {
		t.Fatalf("unsupervised argv = %q", got)
	}
}

func TestGuestRestartPolicyValidation(t *testing.T) {
	for input, want := range map[string]string{"": "never", "never": "never", "on-failure": "on-failure", "always": "always", " ALWAYS ": "always"} {
		got, err := normalizeGuestRestartPolicy(input)
		if err != nil || got != want {
			t.Errorf("normalizeGuestRestartPolicy(%q)=(%q,%v), want %q", input, got, err, want)
		}
	}
	if _, err := normalizeGuestRestartPolicy("sometimes"); err == nil {
		t.Fatal("invalid restart policy was accepted")
	}
	server := &controlServer{}
	if err := server.startWorkload(context.Background(), Request{Argv: []string{"true"}, RestartPolicy: "always"}); err == nil || !strings.Contains(err.Error(), "requires the guest supervisor") {
		t.Fatalf("unsupervised restart policy error=%v", err)
	}
}

func TestSupervisorReadinessRequiresPrivateRegularMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if ready, err := readSupervisorReadiness(path); err != nil || ready {
		t.Fatalf("missing readiness marker=(%v,%v), want false,nil", ready, err)
	}
	if err := os.WriteFile(path, []byte(supervisorReadyContents), 0o600); err != nil {
		t.Fatal(err)
	}
	if ready, err := readSupervisorReadiness(path); err != nil || !ready {
		t.Fatalf("valid readiness marker=(%v,%v), want true,nil", ready, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSupervisorReadiness(path); err == nil {
		t.Fatal("world-readable readiness marker was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, err := readSupervisorReadiness(path); err == nil {
		t.Fatal("symlink readiness marker was accepted")
	}
}

func TestWaitForSupervisorReadinessHonorsContextAndProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForSupervisorReadiness(ctx, path, make(chan struct{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness wait error=%v, want context canceled", err)
	}
	done := make(chan struct{})
	close(done)
	if err := waitForSupervisorReadiness(context.Background(), path, done); err == nil || !strings.Contains(err.Error(), "exited before") {
		t.Fatalf("exited readiness wait error=%v", err)
	}
}

func TestStartWorkloadWaitsForSupervisorReadiness(t *testing.T) {
	root := t.TempDir()
	readyPath := filepath.Join(root, "run", "supervisor.ready")
	supervisorPath := filepath.Join(root, "fake-supervisor")
	script := "#!/bin/sh\numask 077\nprintf '" + supervisorReadyContents + "' > \"$CAUTEM_VM_SUPERVISOR_READY_FILE\"\nexec sleep 30\n"
	if err := os.WriteFile(supervisorPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{
		supervisorEnabled: true,
		supervisorReady:   readyPath,
		workloadCommand: func([]string, bool) []string {
			return []string{supervisorPath}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.startWorkload(ctx, Request{Argv: []string{"ignored"}, WorkDir: root}); err != nil {
		t.Fatalf("startWorkload() error=%v", err)
	}
	if _, err := os.Lstat(readyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness marker remains after acknowledgement: %v", err)
	}
	if err := server.stopWorkload(); err != nil {
		t.Fatalf("stop ready workload: %v", err)
	}
}

func TestGuestCopyRoundTripAndRejectSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "file.txt")
	if err := guestCopyTo(path, []byte("payload"), 0o640, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	data, err := guestCopyFrom(path)
	if err != nil || string(data) != "payload" {
		t.Fatalf("copy roundtrip = (%q, %v)", data, err)
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := guestCopyFrom(filepath.Join(root, "link")); err == nil {
		t.Fatal("copy-from followed a symlink")
	}
}

func TestGuestCopyRejectsSymlinkParentsWithoutTouchingTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(outside, "protected.txt")
	if err := os.WriteFile(protected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	redirected := filepath.Join(root, "redirect", "protected.txt")
	if err := guestCopyTo(redirected, []byte("overwrite"), 0o600, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("copy-to followed a symlink parent")
	}
	if data, err := guestCopyFrom(redirected); err == nil {
		t.Fatalf("copy-from followed a symlink parent: %q", data)
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != "keep" {
		t.Fatalf("outside file changed: data=%q err=%v", data, err)
	}
}

func TestGuestCopyToRejectsFinalSymlinkWithoutTruncatingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := guestCopyTo(link, []byte("overwrite"), 0o600, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("copy-to followed a final symlink")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}
}

func TestGuestExecReturnsStreamsAndExitCode(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv:    []string{"/bin/sh", "-c", "printf out; printf err >&2; exit 7"},
		WorkDir: t.TempDir(),
	})
	if response.Error != "" || response.ExitCode != 7 || string(response.Stdout) != "out" || string(response.Stderr) != "err" {
		t.Fatalf("exec response = %+v", response)
	}
}

func TestGuestShellCommandQuotesArgvAndSelectsLoginMode(t *testing.T) {
	argv := []string{"printf", "%s", "a b'c; $(touch /tmp/should-not-exist)"}
	login := guestShellCommandWithPath("/bin/bash", argv, false)
	if len(login) != 3 || login[0] != "/bin/bash" || login[1] != "-lc" || login[2] != `'printf' '%s' 'a b'"'"'c; $(touch /tmp/should-not-exist)'` {
		t.Fatalf("login shell argv = %q", login)
	}
	plain := guestShellCommandWithPath("/bin/bash", argv, true)
	if len(plain) != 3 || plain[0] != "/bin/bash" || plain[1] != "-c" || plain[2] != login[2] {
		t.Fatalf("non-login shell argv = %q", plain)
	}
}

func TestGuestExecLoginShellReadsProfile(t *testing.T) {
	shellArgv, err := guestShellCommand([]string{"/bin/sh", "-c", `printf '%s' "$QUARSHELL_LOGIN_PROFILE"`}, false)
	if err != nil {
		t.Fatalf("resolve guest login shell: %v", err)
	}
	if shellArgv[0] != "/bin/bash" && shellArgv[0] != "/usr/bin/bash" {
		t.Skipf("profile fixture expects bash, found %s", shellArgv[0])
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".bash_profile"), []byte("export QUARSHELL_LOGIN_PROFILE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv: []string{"/bin/sh", "-c", `printf '%s' "$QUARSHELL_LOGIN_PROFILE"`}, WorkDir: t.TempDir(), Env: []string{"HOME=" + home},
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "loaded" {
		t.Fatalf("login profile exec response = %+v", response)
	}
	response = server.exec(context.Background(), Request{
		Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_LOGIN_PROFILE-unset}"`}, WorkDir: t.TempDir(), Env: []string{"HOME=" + home}, NoLoginShell: true,
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "unset" {
		t.Fatalf("non-login profile exec response = %+v", response)
	}
}

func TestGuestExecTreatsShellMetacharactersAsArguments(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "should-not-exist")
	argument := "$(touch " + marker + "); a'b"
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv: []string{"printf", "%s", argument}, WorkDir: t.TempDir(), NoLoginShell: true,
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != argument {
		t.Fatalf("exec response = %+v", response)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("shell metacharacter created marker: stat error=%v", err)
	}
}

func TestGuestExecFeedsNonInteractiveStdin(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	response := server.exec(context.Background(), Request{
		Argv:    []string{"/bin/sh", "-c", "read value; printf '%s' \"$value\""},
		WorkDir: t.TempDir(), Stdin: []byte("from-client\n"),
	})
	if response.Error != "" || response.ExitCode != 0 || string(response.Stdout) != "from-client" {
		t.Fatalf("stdin exec response = %+v", response)
	}
}

func TestGuestInteractiveExecCreatesAndResizesPTY(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("a", 64),
	}
	guest, host := net.Pipe()
	defer host.Close()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go server.serve(guest)
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
		Argv:    []string{"/bin/sh", "-c", "stty size; IFS= read -r line; stty size"},
		WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := ReadFrame(host)
	if err != nil {
		t.Fatalf("read terminal handshake: %v", err)
	}
	var handshake Response
	if err := json.Unmarshal(handshakePayload, &handshake); err != nil || handshake.Error != "" || handshake.PID <= 0 {
		t.Fatalf("terminal handshake = %+v; decode error=%v", handshake, err)
	}

	readTerminalFrame := func() TerminalFrame {
		t.Helper()
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read terminal frame: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatalf("decode terminal frame: %v", err)
		}
		return frame
	}
	first := readTerminalFrame()
	if first.Type != "output" || !strings.Contains(string(first.Data), "24 80") {
		t.Fatalf("initial terminal output = %+v; want 24 rows and 80 columns", first)
	}
	for _, frame := range []TerminalFrame{
		{Type: "resize", Columns: 101, Rows: 41},
		{Type: "stdin", Data: []byte("resize-check\n")},
	} {
		payload, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(host, payload); err != nil {
			t.Fatalf("send terminal %s frame: %v", frame.Type, err)
		}
	}
	var output strings.Builder
	for {
		frame := readTerminalFrame()
		if frame.Type == "exit" {
			if frame.ExitCode != 0 {
				t.Fatalf("interactive command exit code = %d", frame.ExitCode)
			}
			break
		}
		if frame.Type != "output" {
			t.Fatalf("unexpected terminal frame: %+v", frame)
		}
		output.Write(frame.Data)
	}
	if !strings.Contains(output.String(), "41 101") {
		t.Fatalf("resized terminal output = %q; want 41 rows and 101 columns", output.String())
	}
}

func TestGuestInteractiveExecDrainsOutputBeforeExitFrame(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("c", 64),
	}
	for index := 0; index < 25; index++ {
		t.Run(fmt.Sprintf("run-%02d", index), func(t *testing.T) {
			guest, host := net.Pipe()
			defer host.Close()
			if err := host.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go server.serve(guest)
			marker := fmt.Sprintf("terminal-output-%02d", index)
			request, err := json.Marshal(Request{
				Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
				Argv: []string{"/bin/sh", "-c", "printf " + marker}, WorkDir: t.TempDir(),
				NoLoginShell: true, Columns: 80, Rows: 24,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFrame(host, request); err != nil {
				t.Fatalf("write terminal request: %v", err)
			}
			if payload, err := ReadFrame(host); err != nil {
				t.Fatalf("read terminal handshake: %v", err)
			} else {
				var response Response
				if err := json.Unmarshal(payload, &response); err != nil || response.Error != "" || response.PID <= 0 {
					t.Fatalf("terminal handshake = %+v; decode error=%v", response, err)
				}
			}
			var output strings.Builder
			for {
				payload, err := ReadFrame(host)
				if err != nil {
					t.Fatalf("read terminal output after %q: %v", output.String(), err)
				}
				var frame TerminalFrame
				if err := json.Unmarshal(payload, &frame); err != nil {
					t.Fatalf("decode terminal frame: %v", err)
				}
				switch frame.Type {
				case "output":
					output.Write(frame.Data)
				case "exit":
					if frame.ExitCode != 0 || !strings.Contains(output.String(), marker) {
						t.Fatalf("terminal exit = %d, output = %q; want marker %q before exit", frame.ExitCode, output.String(), marker)
					}
					return
				default:
					t.Fatalf("unexpected terminal frame: %+v", frame)
				}
			}
		})
	}
}

func TestGuestInteractiveExecForwardsTerminalInterrupt(t *testing.T) {
	server := &controlServer{
		uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), token: strings.Repeat("b", 64),
	}
	guest, host := net.Pipe()
	defer host.Close()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go server.serve(guest)
	request, err := json.Marshal(Request{
		Version: ProtocolVersion, AuthToken: server.token, Operation: "exec-terminal",
		Argv:    []string{"/bin/sh", "-c", "trap 'printf interrupted; exit 42' INT; printf 'ready\\n'; while :; do sleep 1; done"},
		WorkDir: t.TempDir(), NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, request); err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := ReadFrame(host)
	if err != nil {
		t.Fatalf("read terminal handshake: %v", err)
	}
	var handshake Response
	if err := json.Unmarshal(handshakePayload, &handshake); err != nil || handshake.Error != "" || handshake.PID <= 0 {
		t.Fatalf("terminal handshake = %+v; decode error=%v", handshake, err)
	}
	var output strings.Builder
	for !strings.Contains(output.String(), "ready") {
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read interactive command readiness from %q: %v", output.String(), err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil || frame.Type != "output" {
			t.Fatalf("readiness terminal frame = %+v; decode error=%v", frame, err)
		}
		output.Write(frame.Data)
	}
	interrupt, _ := json.Marshal(TerminalFrame{Type: "stdin", Data: []byte{3}})
	if err := WriteFrame(host, interrupt); err != nil {
		t.Fatalf("send terminal interrupt: %v", err)
	}
	for {
		payload, err := ReadFrame(host)
		if err != nil {
			t.Fatalf("read terminal output after interrupt: %v", err)
		}
		var frame TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case "output":
			output.Write(frame.Data)
		case "exit":
			if frame.ExitCode != 42 || !strings.Contains(output.String(), "interrupted") {
				t.Fatalf("interrupt result = exit %d, output %q; want trap exit 42", frame.ExitCode, output.String())
			}
			return
		default:
			t.Fatalf("unexpected terminal frame after interrupt: %+v", frame)
		}
	}
}

func TestGuestExecOutputBufferIsBounded(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdefgh")); written != 8 || err != nil {
		t.Fatalf("Write() = (%d, %v)", written, err)
	}
	if string(buffer.data) != "abcd" || !buffer.truncated {
		t.Fatalf("bounded output = (%q, truncated=%t)", buffer.data, buffer.truncated)
	}
}

func TestGuestExecCancellationKillsProcessGroup(t *testing.T) {
	server := &controlServer{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan Response, 1)
	go func() {
		finished <- server.exec(ctx, Request{Argv: []string{"/bin/sh", "-c", "sleep 30"}, WorkDir: t.TempDir()})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case response := <-finished:
		if response.Error != "" || response.ExitCode == 0 {
			t.Fatalf("unexpected cancellation response: %+v", response)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guest exec did not stop after client cancellation")
	}
}
