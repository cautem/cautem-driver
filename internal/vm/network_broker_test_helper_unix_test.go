//go:build darwin || linux

package vm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-proxy/proxy"
)

func TestMain(m *testing.M) {
	if os.Getenv("CAUTEM_VM_TEST_BROKER_LOSS_HELPER") == "1" {
		os.Exit(runNetworkBrokerLossTestHelper())
	}
	if os.Getenv("CAUTEM_VM_TEST_POLICY_PROXY_HELPER") == "1" {
		os.Exit(runPolicyProxyTestHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runNetworkBrokerLossTestHelper() int {
	pidFile := os.Getenv("CAUTEM_VM_TEST_BROKER_PID_FILE")
	if pidFile == "" {
		return 2
	}
	command := exec.Command("sleep", "60")
	if err := command.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	identity := fmt.Sprintf("%d %d %d", command.Process.Pid, os.Getpid(), syscall.Getpgrp())
	if err := os.WriteFile(pidFile, []byte(identity), 0o600); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	process := &networkBrokerProcess{command: command, done: make(chan struct{})}
	go func() {
		process.mu.Lock()
		process.err = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	// The go test binary installs signal handlers; restore the worker's default
	// SIGTERM behavior before exercising the worker process group.
	signal.Reset(syscall.SIGTERM)
	watchNetworkBroker(process, make(chan struct{}))
	select {}
}

func TestWatchNetworkBrokerStopsWorkerProcessGroupOnBrokerLoss(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "broker.pid")
	helper := exec.Command(os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(),
		"CAUTEM_VM_TEST_BROKER_LOSS_HELPER=1",
		"CAUTEM_VM_TEST_BROKER_PID_FILE="+pidFile,
	)
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stderr bytes.Buffer
	helper.Stderr = &stderr
	if err := helper.Start(); err != nil {
		t.Fatalf("start isolated VM worker helper: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- helper.Wait() }()
	helperExited := false
	defer func() {
		if !helperExited {
			_ = syscall.Kill(-helper.Process.Pid, syscall.SIGKILL)
			<-waited
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	var brokerPID int
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) != 3 {
				t.Fatalf("invalid worker/broker process identity %q", data)
			}
			brokerPID, err = strconv.Atoi(fields[0])
			helperPID, helperPIDErr := strconv.Atoi(fields[1])
			groupID, groupErr := strconv.Atoi(fields[2])
			if err != nil || helperPIDErr != nil || groupErr != nil || brokerPID <= 0 {
				t.Fatalf("invalid broker helper PID %q: %v", data, err)
			}
			if helperPID != helper.Process.Pid || groupID != helper.Process.Pid {
				t.Fatalf("worker process identity = pid %d, process group %d; helper pid %d", helperPID, groupID, helper.Process.Pid)
			}
			break
		}
		select {
		case err := <-waited:
			helperExited = true
			t.Fatalf("worker helper exited before starting broker: %v stderr=%q", err, stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if brokerPID == 0 {
		t.Fatalf("worker helper did not publish broker PID: stderr=%q", stderr.String())
	}
	broker, err := os.FindProcess(brokerPID)
	if err != nil {
		t.Fatalf("find broker helper process: %v", err)
	}
	if err := broker.Kill(); err != nil {
		t.Fatalf("kill policy broker helper: %v", err)
	}
	select {
	case err := <-waited:
		helperExited = true
		if err == nil {
			t.Fatal("worker helper exited successfully after broker loss")
		}
		status, ok := helper.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
			t.Fatalf("worker helper exit after broker loss = %v (status=%v), want SIGTERM; stderr=%q", err, helper.ProcessState, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker process group did not stop after policy broker loss")
	}
}

func runPolicyProxyTestHelper(args []string) int {
	var socket, policyPath string
	for index := 0; index+1 < len(args); index++ {
		switch args[index] {
		case "--listen":
			if strings.HasPrefix(args[index+1], "unix://") {
				socket = strings.TrimPrefix(args[index+1], "unix://")
			}
		case "--policy":
			policyPath = args[index+1]
		}
	}
	if socket == "" || policyPath == "" {
		fmt.Fprintln(os.Stderr, "VM policy proxy test helper requires a Unix socket listener and policy file")
		return 2
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.Remove(socket) }()
	document, err := policy.Load(policyPath)
	if err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := document.Validate(); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var allowlist engine.Allowlist
	if err := allowlist.Apply(document); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	server := proxy.NewServer(&allowlist, os.Stderr)
	if pidFile := os.Getenv("CAUTEM_VM_TEST_BROKER_PID_FILE"); pidFile != "" {
		if !filepath.IsAbs(pidFile) || filepath.Clean(pidFile) != pidFile {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, "VM policy proxy test broker PID path must be a clean absolute path")
			return 1
		}
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			_ = listener.Close()
			fmt.Fprintf(os.Stderr, "publish VM policy proxy test broker PID: %v\n", err)
			return 1
		}
	}
	var controlServer net.Listener
	controlPath := os.Getenv("CAUTEM_SUPERVISOR_CONTROL_SOCKET")
	if controlPath != "" {
		controlServer, err = net.Listen("unix", controlPath)
		if err != nil {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = os.Remove(controlPath) }()
		if err := os.Chmod(controlPath, 0o600); err != nil {
			_ = controlServer.Close()
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		go serveSupervisorControlTestHelper(controlServer, os.Getenv("CAUTEM_VM_TEST_CONTROL_EVENTS"))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if ackPath := os.Getenv("CAUTEM_VM_TEST_POLICY_ACK_FILE"); ackPath != "" {
		if !filepath.IsAbs(ackPath) || filepath.Clean(ackPath) != ackPath {
			_ = listener.Close()
			fmt.Fprintln(os.Stderr, "VM policy proxy test acknowledgement path must be a clean absolute path")
			return 1
		}
		server.ReportPolicyStatus = func(_ context.Context, revision uint32, loadError string) error {
			status := "loaded"
			if loadError != "" {
				status = "failed"
			}
			return os.WriteFile(ackPath, []byte(fmt.Sprintf("%d %s\n", revision, status)), 0o600)
		}
		go server.WatchPolicy(ctx, policyPath, 25*time.Millisecond)
	}
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- server.Serve(ctx, listener) }()
	go func() {
		<-ctx.Done()
		if controlServer != nil {
			_ = controlServer.Close()
		}
	}()
	err = <-proxyDone
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func TestNetworkBrokerTestHelperEnforcesDefaultDeny(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vmp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "proxy.sock")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^$")
	command.Args = append(command.Args, "proxy", "--listen", "unix://"+socket, "--policy", policyPath)
	command.Env = append(os.Environ(), "CAUTEM_VM_TEST_POLICY_PROXY_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start actual policy proxy helper: %v", err)
	}
	defer func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		waited := make(chan struct{})
		go func() { _ = command.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-waited
		}
	}()
	if err := waitForProxySocket(ctx, socket); err != nil {
		t.Fatalf("%v; helper stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		t.Fatalf("connect to actual policy proxy: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(connection, "GET http://policy-probe.invalid/ HTTP/1.1\r\nHost: policy-probe.invalid\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read default-deny response from actual policy proxy: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "cautem-proxy: denied") {
		t.Fatalf("actual proxy default-deny response = status %d body=%q readErr=%v", response.StatusCode, body, readErr)
	}
}

func waitForProxySocket(ctx context.Context, socket string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("policy proxy helper did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type supervisorControlTestRequest struct {
	Operation  string `json:"operation"`
	InstanceID string `json:"instance_id,omitempty"`
	ExitCode   int32  `json:"exit_code,omitempty"`
}

type supervisorControlTestResponse struct {
	InstanceID string `json:"instance_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

func serveSupervisorControlTestHelper(listener net.Listener, eventPath string) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(connection, 8<<10)).ReadBytes('\n')
			if err != nil {
				_ = json.NewEncoder(connection).Encode(supervisorControlTestResponse{Error: "invalid supervisor control request"})
				return
			}
			var request supervisorControlTestRequest
			if err := json.Unmarshal(line, &request); err != nil || request.Operation == "" {
				_ = json.NewEncoder(connection).Encode(supervisorControlTestResponse{Error: "invalid supervisor control request"})
				return
			}
			if eventPath != "" {
				file, openErr := os.OpenFile(eventPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if openErr == nil {
					_, _ = fmt.Fprintln(file, request.Operation)
					_ = file.Close()
				}
			}
			response := supervisorControlTestResponse{}
			if request.Operation == "begin" {
				response.InstanceID = "live-vm-instance"
			}
			_ = json.NewEncoder(connection).Encode(response)
		}()
	}
}
