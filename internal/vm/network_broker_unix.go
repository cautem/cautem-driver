//go:build darwin || linux

package vm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const networkBrokerWait = 20 * time.Second

type networkBrokerProcess struct {
	command  *exec.Cmd
	done     chan struct{}
	mu       sync.Mutex
	err      error
	stopping atomic.Bool
}

func startNetworkBroker(config *networkBrokerConfig) (*networkBrokerProcess, error) {
	if config == nil {
		return nil, nil
	}
	validated, err := validateNetworkBrokerConfig(*config)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(validated.Socket)); err != nil {
		return nil, fmt.Errorf("secure policy proxy socket directory: %w", err)
	}
	if err := ensurePrivateDirectory(validated.LogDir); err != nil {
		return nil, fmt.Errorf("secure policy proxy log directory: %w", err)
	}
	if err := removeStaleUnixSocket(validated.Socket); err != nil {
		return nil, fmt.Errorf("prepare policy proxy socket: %w", err)
	}
	proxyEnv, err := networkBrokerProcessEnvironment(validated)
	if err != nil {
		return nil, err
	}
	command := exec.Command(validated.Binary,
		"proxy", "--listen", "unix://"+validated.Socket,
		"--policy", validated.Policy,
		"--log-dir", validated.LogDir,
		"--gateway-host-mode",
	)
	command.Env = proxyEnv
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start VM policy proxy: %w", err)
	}
	process := &networkBrokerProcess{command: command, done: make(chan struct{})}
	go func() {
		process.mu.Lock()
		process.err = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	if err := waitForNetworkBroker(process, validated.Socket, networkBrokerWait); err != nil {
		stopNetworkBroker(process)
		return nil, err
	}
	if validated.ControlSocket != "" {
		if err := waitForProxyControlSocket(process, validated.ControlSocket, networkBrokerWait); err != nil {
			stopNetworkBroker(process)
			return nil, err
		}
	}
	return process, nil
}

func networkBrokerProcessEnvironment(config networkBrokerConfig) ([]string, error) {
	entries := append([]string(nil), config.ProxyEnv...)
	if config.SSHSocket != "" {
		entries = append(entries, "CAUTEM_SSH_SOCKET="+config.SSHSocket)
	}
	if config.ControlSocket != "" {
		entries = append(entries, "CAUTEM_SUPERVISOR_CONTROL_SOCKET="+config.ControlSocket)
	}
	return networkBrokerEnvironmentChecked(entries)
}

func waitForProxyControlSocket(process *networkBrokerProcess, socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", socket)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-process.done:
			exitErr := process.wait()
			if exitErr == nil {
				exitErr = fmt.Errorf("proxy exited without an error")
			}
			return fmt.Errorf("VM supervisor control socket unavailable because proxy exited: %w", exitErr)
		case <-ctx.Done():
			return fmt.Errorf("VM supervisor control socket did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func validateNetworkBrokerConfig(config networkBrokerConfig) (networkBrokerConfig, error) {
	binary, err := validateExecutablePath(config.Binary)
	if err != nil {
		return config, fmt.Errorf("VM policy proxy: %w", err)
	}
	config.Binary = binary
	if config.Policy == "" || !filepath.IsAbs(config.Policy) || filepath.Clean(config.Policy) != config.Policy {
		return config, fmt.Errorf("VM policy proxy path must be a clean absolute path")
	}
	policyInfo, err := os.Lstat(config.Policy)
	if err != nil {
		return config, fmt.Errorf("inspect VM policy file: %w", err)
	}
	if !policyInfo.Mode().IsRegular() || policyInfo.Mode()&os.ModeSymlink != 0 || policyInfo.Size() == 0 || policyInfo.Size() > 4<<20 || policyInfo.Mode().Perm()&0o022 != 0 {
		return config, fmt.Errorf("VM policy file must be a non-empty regular file no larger than 4 MiB and not writable by group or others")
	}
	policyDir, err := os.Lstat(filepath.Dir(config.Policy))
	if err != nil || !policyDir.IsDir() || policyDir.Mode()&os.ModeSymlink != 0 || policyDir.Mode().Perm()&0o077 != 0 || !networkPathOwnedByCurrentUser(policyDir) {
		return config, fmt.Errorf("VM policy directory must be a private directory owned by the current user")
	}
	if config.Socket == "" || !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket || len(config.Socket) > 96 {
		return config, fmt.Errorf("VM policy proxy socket must be a clean absolute path within the Unix socket path limit")
	}
	socketDir, err := os.Lstat(filepath.Dir(config.Socket))
	if err != nil || !socketDir.IsDir() || socketDir.Mode()&os.ModeSymlink != 0 || socketDir.Mode().Perm()&0o077 != 0 || !networkPathOwnedByCurrentUser(socketDir) {
		return config, fmt.Errorf("VM policy proxy socket directory must be private and owned by the current user")
	}
	for name, path := range map[string]string{"SSH relay": config.SSHSocket, "supervisor control": config.ControlSocket} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 96 || strings.IndexByte(path, 0) >= 0) {
			return config, fmt.Errorf("VM %s socket must be a clean absolute path within the Unix socket path limit", name)
		}
		if path != "" && filepath.Dir(path) != filepath.Dir(config.Socket) {
			return config, fmt.Errorf("VM %s socket must share the private policy proxy socket directory", name)
		}
	}
	if config.LogDir == "" || !filepath.IsAbs(config.LogDir) {
		return config, fmt.Errorf("VM policy proxy log directory must be absolute")
	}
	for _, entry := range config.ProxyEnv {
		key, _, _ := strings.Cut(entry, "=")
		if key == "CAUTEM_SSH_SOCKET" || key == "CAUTEM_SUPERVISOR_CONTROL_SOCKET" {
			return config, fmt.Errorf("VM policy proxy environment cannot override the %s socket", key)
		}
	}
	if _, err := networkBrokerProcessEnvironment(config); err != nil {
		return config, err
	}
	return config, nil
}

func waitForNetworkBroker(process *networkBrokerProcess, socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-process.done:
			err := process.wait()
			if err == nil {
				err = fmt.Errorf("proxy exited without an error")
			}
			return fmt.Errorf("VM policy proxy exited before readiness: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("VM policy proxy did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func checkNetworkBrokerHealth(ctx context.Context, socket string) error {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := io.WriteString(connection, "GET /healthz HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy health check returned %s", response.Status)
	}
	return nil
}

func stopNetworkBroker(process *networkBrokerProcess) {
	if process == nil || process.command == nil || process.command.Process == nil {
		return
	}
	process.stopping.Store(true)
	_ = process.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-process.done:
	case <-time.After(2 * time.Second):
		_ = process.command.Process.Kill()
		<-process.done
	}
}

func watchNetworkBroker(process *networkBrokerProcess, stopping <-chan struct{}) {
	if process == nil {
		return
	}
	select {
	case <-process.done:
		if process.stopping.Load() {
			return
		}
		err := process.wait()
		if err == nil {
			err = fmt.Errorf("exited without an error")
		}
		fmt.Fprintf(os.Stderr, "VM policy proxy stopped: %v\n", err)
		if err := syscall.Kill(-os.Getpid(), syscall.SIGTERM); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop VM worker process group after policy proxy loss: %v\n", err)
		}
	case <-stopping:
	}
}

func networkBrokerEnvironment(entries []string) []string {
	environment, _ := networkBrokerEnvironmentChecked(entries)
	return environment
}

func networkBrokerEnvironmentChecked(entries []string) ([]string, error) {
	if err := validateNetworkBrokerEnvironment(entries); err != nil {
		return nil, err
	}
	values := map[string]string{"PATH": "/usr/bin:/bin"}
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func networkPathOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func (process *networkBrokerProcess) wait() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}
