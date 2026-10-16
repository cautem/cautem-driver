//go:build linux

package vmguest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	userdb "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// RunGuestAgent serves the VM control protocol on virtio-vsock. It is built as
// a static Linux binary and injected into each prepared rootfs by the host.
func Run() error {
	proxyPort, brokerPort, err := networkProxyConfigurationFromEnvironment()
	if err != nil {
		return err
	}
	relayConfig, err := relayConfigurationFromEnvironment()
	if err != nil {
		return err
	}
	proxyURL := ""
	if brokerPort != 0 {
		listener, err := startNetworkProxyBridge(proxyPort)
		if err != nil {
			return fmt.Errorf("start guest policy proxy: %w", err)
		}
		proxyURL = "http://127.0.0.1:" + strconv.Itoa(int(proxyPort))
		go serveNetworkProxyBridge(listener, brokerPort)
	}
	if relayConfig.sshPort != 0 {
		if err := startSSHRelayBridge(relayConfig.sshPort); err != nil {
			return fmt.Errorf("start guest SSH relay: %w", err)
		}
	}
	supervisorSocket := ""
	if relayConfig.controlPort != 0 {
		supervisorSocket, err = startSupervisorControlBridge(relayConfig.controlPort)
		if err != nil {
			return fmt.Errorf("start guest supervisor control relay: %w", err)
		}
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create guest vsock: %w", err)
	}
	defer unix.Close(fd)
	address := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: ControlPort}
	if err := unix.Bind(fd, address); err != nil {
		return fmt.Errorf("bind guest vsock port %d: %w", ControlPort, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return fmt.Errorf("listen on guest vsock: %w", err)
	}
	uid, gid := guestIdentity()
	token := os.Getenv("CAUTEM_VM_CONTROL_TOKEN")
	_ = os.Unsetenv("CAUTEM_VM_CONTROL_TOKEN")
	decodedToken, err := hex.DecodeString(token)
	if err != nil || len(decodedToken) != 32 {
		return fmt.Errorf("guest control token is missing or invalid")
	}
	server := &controlServer{
		uid: uid, gid: gid, token: token, proxyURL: proxyURL,
		supervisorSocket: supervisorSocket, supervisorEnabled: relayConfig.supervisor,
		sshEnabled: relayConfig.sshPort != 0,
	}
	for {
		connectionFD, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return fmt.Errorf("accept guest control connection: %w", err)
		}
		go server.serve(&guestVsockConn{File: os.NewFile(uintptr(connectionFD), "guest-vsock-client")})
	}
}

type guestVsockConn struct{ *os.File }

func (*guestVsockConn) LocalAddr() net.Addr              { return guestVsockAddr("local") }
func (*guestVsockConn) RemoteAddr() net.Addr             { return guestVsockAddr("remote") }
func (*guestVsockConn) SetDeadline(time.Time) error      { return nil }
func (*guestVsockConn) SetReadDeadline(time.Time) error  { return nil }
func (*guestVsockConn) SetWriteDeadline(time.Time) error { return nil }

type guestVsockAddr string

func (addr guestVsockAddr) Network() string { return "vsock" }
func (addr guestVsockAddr) String() string  { return string(addr) }

func guestIdentity() (uint32, uint32) {
	uid, _ := strconv.ParseUint(os.Getenv("CAUTEM_VM_UID"), 10, 32)
	gid, _ := strconv.ParseUint(os.Getenv("CAUTEM_VM_GID"), 10, 32)
	if uid == 0 {
		uid = 1000
	}
	if gid == 0 {
		gid = uid
	}
	return uint32(uid), uint32(gid)
}

type controlServer struct {
	uid               uint32
	gid               uint32
	token             string
	proxyURL          string
	supervisorSocket  string
	supervisorEnabled bool
	sshEnabled        bool
	supervisorReady   string
	workloadCommand   func([]string, bool) []string
	authMu            sync.RWMutex
	mu                sync.Mutex
	job               *exec.Cmd
	jobDone           chan struct{}
	previousToken     string
	rotationID        string
	sshMu             sync.Mutex
	sshDaemon         *exec.Cmd
}

const execOutputLimit = 8 << 20

const (
	guestSupervisorReadyFile = "/run/cautem/supervisor.ready"
	guestSupervisorReadyEnv  = "CAUTEM_VM_SUPERVISOR_READY_FILE"
	supervisorReadyContents  = "quarshell-supervisor-ready-v1\n"
	supervisorReadyTimeout   = 30 * time.Second
)

type boundedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(payload []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		b.data = append(b.data, payload[:remaining]...)
	}
	if remaining < len(payload) {
		b.truncated = true
	}
	return len(payload), nil
}

func (s *controlServer) serve(connection net.Conn) {
	defer connection.Close()
	encoded, err := ReadFrame(connection)
	if err != nil {
		return
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		_ = writeResponse(connection, Response{Error: "invalid request"})
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		_ = writeResponse(connection, Response{Error: "invalid request framing"})
		return
	}
	if request.Operation == "exec-terminal" {
		if err := s.validateRequest(request); err != nil {
			_ = writeResponse(connection, Response{Error: err.Error()})
			return
		}
		s.execTerminal(connection, request)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var byteBuffer [1]byte
		_, readErr := connection.Read(byteBuffer[:])
		if readErr != nil {
			cancel()
		}
	}()
	response := Response{}
	if err := s.validateRequest(request); err != nil {
		response.Error = err.Error()
	} else {
		response = s.dispatch(ctx, request)
	}
	cancel()
	_ = writeResponse(connection, response)
	_ = connection.Close()
	<-watchDone
	if request.Operation == "shutdown" && response.Error == "" {
		go func() {
			syscall.Sync()
			time.Sleep(100 * time.Millisecond)
			_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		}()
	}
}

func (s *controlServer) validateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf("unsupported control protocol version %d", request.Version)
	}
	if request.Operation != "rotate-token" && (request.NextAuthToken != "" || request.RotationID != "") {
		return fmt.Errorf("token rotation fields are only valid for rotate-token")
	}
	if request.User != "" && request.Operation != "start-workload" && request.Operation != "exec" && request.Operation != "exec-terminal" {
		return fmt.Errorf("workload identity is only valid for workload operations")
	}
	if !s.authorizedRequest(request) {
		return fmt.Errorf("unauthorized guest control request")
	}
	return nil
}

func (s *controlServer) authorized(token string) bool {
	if s == nil {
		return false
	}
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	if len(s.token) != 64 || len(token) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.token), []byte(token)) == 1
}

func (s *controlServer) authorizedRequest(request Request) bool {
	if s.authorized(request.AuthToken) {
		return true
	}
	if s == nil || request.Operation != "rotate-token" || !validControlToken(request.NextAuthToken) || !validRotationID(request.RotationID) {
		return false
	}
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return subtle.ConstantTimeCompare([]byte(s.previousToken), []byte(request.AuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.rotationID), []byte(request.RotationID)) == 1
}

func (s *controlServer) dispatch(ctx context.Context, request Request) Response {
	switch request.Operation {
	case "ping":
		return Response{}
	case "rotate-token":
		if err := s.rotateToken(request); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "start-workload":
		if err := s.startWorkload(ctx, request); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "stop-workload":
		if err := s.stopWorkload(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "start-ssh":
		if err := s.startSSHDaemon(); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "shutdown":
		return Response{}
	case "exec":
		return s.exec(ctx, request)
	case "copy-to":
		if err := guestCopyTo(request.Path, request.Data, request.Mode, s.uid, s.gid); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{}
	case "copy-from":
		data, err := guestCopyFrom(request.Path)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Data: data}
	default:
		return Response{Error: "unsupported operation"}
	}
}

func (s *controlServer) rotateToken(request Request) error {
	if !validControlToken(request.NextAuthToken) || !validRotationID(request.RotationID) {
		return fmt.Errorf("guest control token rotation request is malformed")
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if subtle.ConstantTimeCompare([]byte(s.previousToken), []byte(request.AuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(s.rotationID), []byte(request.RotationID)) == 1 {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(request.AuthToken)) != 1 {
		return fmt.Errorf("guest control token rotation is unauthorized")
	}
	if subtle.ConstantTimeCompare([]byte(s.token), []byte(request.NextAuthToken)) == 1 {
		return fmt.Errorf("guest control token rotation must change the token")
	}
	s.previousToken = s.token
	s.token = request.NextAuthToken
	s.rotationID = request.RotationID
	return nil
}

func validControlToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func validRotationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func (s *controlServer) startWorkload(ctx context.Context, request Request) error {
	if ctx == nil {
		return fmt.Errorf("guest workload start context is nil")
	}
	if len(request.Argv) == 0 {
		return fmt.Errorf("workload argv is empty")
	}
	restartPolicy, err := normalizeGuestRestartPolicy(request.RestartPolicy)
	if err != nil {
		return err
	}
	if restartPolicy != "never" && !s.supervisorEnabled {
		return fmt.Errorf("main process restart policy requires the guest supervisor")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != nil && s.job.Process != nil {
		return fmt.Errorf("sandbox workload is already running")
	}
	readyPath := ""
	if s.supervisorEnabled {
		readyPath = s.supervisorReady
		if readyPath == "" {
			readyPath = guestSupervisorReadyFile
		}
		if err := prepareSupervisorReadiness(readyPath); err != nil {
			return fmt.Errorf("prepare guest supervisor readiness: %w", err)
		}
	}
	buildCommand := guestWorkloadCommand
	if s.workloadCommand != nil {
		buildCommand = s.workloadCommand
	}
	argv := buildCommand(request.Argv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env,
			"CAUTEM_POLICY="+guestPolicyFile,
			"CAUTEM_SUPERVISOR_CONTROL_SOCKET="+s.supervisorSocket,
			"CAUTEM_MAIN_PROCESS_RESTART_POLICY="+restartPolicy,
			guestSupervisorReadyEnv+"="+readyPath,
		)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	}
	command.Dir = guestWorkdir(request.WorkDir)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			return fmt.Errorf("resolve guest workload identity: %w", err)
		}
		command.SysProcAttr.Credential = credential
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start sandbox workload: %w", err)
	}
	s.job = command
	done := make(chan struct{})
	s.jobDone = done
	go func() {
		_ = command.Wait()
		close(done)
		s.mu.Lock()
		if s.job == command {
			s.job = nil
			s.jobDone = nil
		}
		s.mu.Unlock()
	}()
	if s.supervisorEnabled {
		if err := waitForSupervisorReadiness(ctx, readyPath, done); err != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			s.job = nil
			s.jobDone = nil
			_ = os.Remove(readyPath)
			return fmt.Errorf("guest supervisor did not become ready: %w", err)
		}
	}
	return nil
}

func prepareSupervisorReadiness(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("supervisor readiness path is invalid")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("supervisor readiness directory must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace a non-regular supervisor readiness marker")
	}
	return os.Remove(path)
}

func waitForSupervisorReadiness(ctx context.Context, path string, done <-chan struct{}) error {
	timer := time.NewTimer(supervisorReadyTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := readSupervisorReadiness(path)
		if err != nil {
			return err
		}
		if ready {
			return os.Remove(path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return fmt.Errorf("supervisor exited before publishing readiness")
		case <-timer.C:
			return fmt.Errorf("supervisor readiness timed out after %s", supervisorReadyTimeout)
		case <-ticker.C:
		}
	}
}

func readSupervisorReadiness(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), "supervisor-readiness")
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return false, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size > 128 || info.Mode&0o077 != 0 {
		return false, fmt.Errorf("supervisor readiness marker has unsafe type, size or permissions")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return false, err
	}
	if len(contents) < len(supervisorReadyContents) && strings.HasPrefix(supervisorReadyContents, string(contents)) {
		return false, nil
	}
	if string(contents) != supervisorReadyContents {
		return false, fmt.Errorf("supervisor readiness marker has invalid contents")
	}
	return true, nil
}

func normalizeGuestRestartPolicy(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "never":
		return "never", nil
	case "on-failure", "always":
		return strings.ToLower(strings.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("invalid main process restart policy")
	}
}

func (s *controlServer) startSSHDaemon() error {
	if !s.sshEnabled {
		return fmt.Errorf("sandbox has no SSH relay")
	}
	s.sshMu.Lock()
	if s.sshDaemon != nil && s.sshDaemon.Process != nil {
		if connection, err := net.DialTimeout("unix", guestSSHSocket, 150*time.Millisecond); err == nil {
			_ = connection.Close()
			s.sshMu.Unlock()
			return nil
		}
	}
	command := exec.Command(guestSSHBinary,
		"--socket", guestSSHSocket,
		"--init", guestInitBinary,
		"--workdir", "/workspace",
	)
	command.Env = mergeGuestEnvironment(guestEnvironmentForWorkload(nil, s.proxyURL), "CAUTEM_POLICY="+guestPolicyFile)
	command.Dir = "/"
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		s.sshMu.Unlock()
		return fmt.Errorf("start guest SSH daemon: %w", err)
	}
	s.sshDaemon = command
	go func() {
		_ = command.Wait()
		s.sshMu.Lock()
		if s.sshDaemon == command {
			s.sshDaemon = nil
		}
		s.sshMu.Unlock()
	}()
	s.sshMu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", guestSSHSocket, 150*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		s.sshMu.Lock()
		stillRunning := s.sshDaemon == command
		s.sshMu.Unlock()
		if !stillRunning {
			return fmt.Errorf("guest SSH daemon exited before readiness")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("guest SSH socket did not become ready")
}

func (s *controlServer) stopWorkload() error {
	s.mu.Lock()
	command := s.job
	done := s.jobDone
	s.mu.Unlock()
	if command == nil || command.Process == nil {
		return nil
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("stop sandbox workload: %w", err)
	}
	if done != nil {
		select {
		case <-done:
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("force stop sandbox workload: %w", err)
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("sandbox workload did not exit after SIGKILL")
		}
	}
	return nil
}

func (s *controlServer) exec(ctx context.Context, request Request) Response {
	if len(request.Argv) == 0 {
		return Response{Error: "exec argv is empty"}
	}
	shellArgv, err := guestShellCommand(request.Argv, request.NoLoginShell)
	if err != nil {
		return Response{Error: err.Error()}
	}
	argv := guestExecCommand(shellArgv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env, "CAUTEM_POLICY="+guestPolicyFile)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	}
	command.Dir = guestWorkdir(request.WorkDir)
	command.Stdin = bytes.NewReader(request.Stdin)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			return Response{Error: fmt.Sprintf("resolve guest workload identity: %v", err)}
		}
		command.SysProcAttr.Credential = credential
	}
	stdout := boundedBuffer{limit: execOutputLimit}
	stderr := boundedBuffer{limit: execOutputLimit}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if startErr := command.Start(); startErr != nil {
		return Response{Error: startErr.Error()}
	}
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		case <-watchDone:
		}
	}()
	waitErr := command.Wait()
	close(watchDone)
	response := Response{Stdout: stdout.data, Stderr: stderr.data, OutputTruncated: stdout.truncated || stderr.truncated}
	if waitErr == nil {
		return response
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		response.ExitCode = exitError.ExitCode()
		return response
	}
	response.Error = waitErr.Error()
	return response
}

func (s *controlServer) execTerminal(connection net.Conn, request Request) {
	if len(request.Argv) == 0 {
		_ = writeResponse(connection, Response{Error: "exec argv is empty"})
		return
	}
	if request.Columns == 0 || request.Rows == 0 || request.Columns > 65535 || request.Rows > 65535 {
		_ = writeResponse(connection, Response{Error: "terminal dimensions must be between 1 and 65535"})
		return
	}
	shellArgv, err := guestShellCommand(request.Argv, request.NoLoginShell)
	if err != nil {
		_ = writeResponse(connection, Response{Error: err.Error()})
		return
	}
	argv := guestExecCommand(shellArgv, s.supervisorEnabled)
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = guestEnvironmentForWorkload(request.Env, s.proxyURL)
	if s.supervisorEnabled {
		command.Env = mergeGuestEnvironment(command.Env, "CAUTEM_POLICY="+guestPolicyFile)
		if request.User != "" {
			command.Env = mergeGuestEnvironment(command.Env, "OPENSHELL_OCI_IMAGE_USER="+request.User)
		}
	}
	command.Dir = guestWorkdir(request.WorkDir)
	if !s.supervisorEnabled {
		credential, err := guestWorkloadCredential(request.User, s.uid, s.gid)
		if err != nil {
			_ = writeResponse(connection, Response{Error: fmt.Sprintf("resolve guest workload identity: %v", err)})
			return
		}
		command.SysProcAttr = credentialPTYAttributes(credential)
	}
	terminal, err := pty.StartWithSize(command, &pty.Winsize{Cols: uint16(request.Columns), Rows: uint16(request.Rows)})
	if err != nil {
		_ = writeResponse(connection, Response{Error: fmt.Sprintf("start guest PTY command: %v", err)})
		return
	}
	if err := writeResponse(connection, Response{PID: command.Process.Pid}); err != nil {
		_ = terminal.Close()
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return
	}

	processDone := make(chan struct{})
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := terminal.Read(buffer)
			if count > 0 {
				if err := writeTerminalFrame(connection, TerminalFrame{Type: "output", Data: append([]byte(nil), buffer[:count]...)}); err != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			payload, readErr := ReadFrame(connection)
			if readErr != nil {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			var frame TerminalFrame
			decoder := json.NewDecoder(strings.NewReader(string(payload)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&frame); err != nil || decoder.Decode(new(any)) != io.EOF {
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
			switch frame.Type {
			case "stdin":
				if len(frame.Data) > 0 {
					if _, err := terminal.Write(frame.Data); err != nil {
						terminatePTYProcess(command.Process.Pid, processDone)
						return
					}
				}
			case "resize":
				if frame.Columns == 0 || frame.Rows == 0 || frame.Columns > 65535 || frame.Rows > 65535 {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
				if err := pty.Setsize(terminal, &pty.Winsize{Cols: uint16(frame.Columns), Rows: uint16(frame.Rows)}); err != nil {
					terminatePTYProcess(command.Process.Pid, processDone)
					return
				}
			case "eof":
				_, _ = terminal.Write([]byte{4})
			default:
				terminatePTYProcess(command.Process.Pid, processDone)
				return
			}
		}
	}()
	waitErr := command.Wait()
	close(processDone)
	// The process may exit before the PTY reader drains its last buffered
	// bytes; emit the exit frame only after that reader reaches EOF/EIO.
	<-outputDone
	_ = terminal.Close()
	_ = writeTerminalFrame(connection, TerminalFrame{Type: "exit", ExitCode: normalizeGuestExitCode(waitErr)})
	_ = connection.Close()
	<-inputDone
}

func writeTerminalFrame(writer io.Writer, frame TerminalFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return WriteFrame(writer, encoded)
}

func terminatePTYProcess(pid int, done <-chan struct{}) {
	if pid <= 1 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}

func normalizeGuestExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitError.ExitCode()
	}
	return 255
}

func credentialPTYAttributes(credential *syscall.Credential) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: credential}
}

func guestCopyTo(path string, data []byte, mode, uid, gid uint32) error {
	clean, err := cleanGuestPath(path)
	if err != nil {
		return err
	}
	if len(data) > FrameMax/2 {
		return fmt.Errorf("copy-to payload exceeds %d bytes", FrameMax/2)
	}
	parentFD, name, err := openGuestParent(clean, true)
	if err != nil {
		return fmt.Errorf("open guest destination directory: %w", err)
	}
	defer unix.Close(parentFD)
	mode &= 0o777
	if mode == 0 {
		mode = 0o644
	}
	fd, err := openGuestFileForWrite(parentFD, name, mode)
	if err != nil {
		return fmt.Errorf("open guest destination: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return fmt.Errorf("inspect guest destination: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("guest destination must be a regular file")
	}
	if err := unix.Ftruncate(fd, 0); err != nil {
		return fmt.Errorf("truncate guest destination: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write guest destination: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync guest destination: %w", err)
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return fmt.Errorf("set guest destination owner: %w", err)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("set guest destination mode: %w", err)
	}
	return nil
}

func openGuestFileForWrite(parentFD int, name string, mode uint32) (int, error) {
	pathFD, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		// O_EXCL ensures a file created between the O_PATH lookup and this call
		// cannot redirect the write through a symlink or device node.
		return unix.Openat(parentFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
	}
	if err != nil {
		return -1, err
	}
	defer unix.Close(pathFD)
	var info unix.Stat_t
	if err := unix.Fstat(pathFD, &info); err != nil {
		return -1, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, fmt.Errorf("guest destination must be a regular file")
	}
	// Reopen the already-verified inode through procfs so a concurrent rename
	// cannot substitute a different path between validation and writing.
	return unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

func guestCopyFrom(path string) ([]byte, error) {
	clean, err := cleanGuestPath(path)
	if err != nil {
		return nil, err
	}
	parentFD, name, err := openGuestParent(clean, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size > FrameMax/2 {
		return nil, fmt.Errorf("guest source must be a regular file no larger than %d bytes", FrameMax/2)
	}
	data, err := io.ReadAll(io.LimitReader(file, FrameMax/2+1))
	if err != nil {
		return nil, err
	}
	if len(data) > FrameMax/2 {
		return nil, fmt.Errorf("guest source grew beyond %d bytes", FrameMax/2)
	}
	return data, nil
}

// openGuestParent walks from the guest root one directory at a time. O_NOFOLLOW
// prevents a workload-created symlink from redirecting a privileged copy
// operation outside the requested path hierarchy.
func openGuestParent(path string, create bool) (int, string, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[len(components)-1] == "" {
		return -1, "", fmt.Errorf("guest path has no file name")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open guest root: %w", err)
	}
	parentFD := rootFD
	for _, component := range components[:len(components)-1] {
		childFD, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(parentFD, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(parentFD)
				return -1, "", fmt.Errorf("create guest destination directory: %w", mkdirErr)
			}
			childFD, openErr = unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(parentFD)
			return -1, "", fmt.Errorf("resolve guest path component %q: %w", component, openErr)
		}
		_ = unix.Close(parentFD)
		parentFD = childFD
	}
	return parentFD, components[len(components)-1], nil
}

func cleanGuestPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", fmt.Errorf("guest path must be a clean absolute file path")
	}
	return path, nil
}

func guestEnvironment(overrides []string) []string {
	values := map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/workspace", "USER": "sandbox"}
	for _, entry := range overrides {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			values[key] = value
		}
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func guestEnvironmentForWorkload(overrides []string, proxyURL string) []string {
	values := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": "/workspace",
		"USER": "sandbox",
	}
	for _, entry := range overrides {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.HasPrefix(key, "CAUTEM_VM_") || isGuestIdentityEnvironment(key) {
			continue
		}
		values[key] = value
	}
	if proxyURL != "" {
		for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			values[key] = proxyURL
		}
		values["NO_PROXY"] = "localhost,127.0.0.1,::1"
		values["no_proxy"] = values["NO_PROXY"]
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func isGuestIdentityEnvironment(key string) bool {
	switch key {
	case "OPENSHELL_OCI_IMAGE_USER", "OPENSHELL_SANDBOX_UID", "OPENSHELL_SANDBOX_GID":
		return true
	default:
		return false
	}
}

func guestWorkloadCredential(declaration string, defaultUID, defaultGID uint32) (*syscall.Credential, error) {
	if declaration == "" {
		return &syscall.Credential{Uid: defaultUID, Gid: defaultGID}, nil
	}
	parts := strings.Split(declaration, ":")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return nil, fmt.Errorf("OCI user declaration is malformed")
	}
	for _, part := range parts {
		if strings.TrimSpace(part) != part || strings.IndexByte(part, 0) >= 0 || strings.ContainsAny(part, "\r\n") {
			return nil, fmt.Errorf("OCI user declaration is malformed")
		}
		for _, char := range part {
			if char < 0x21 || char == 0x7f || char == ':' {
				return nil, fmt.Errorf("OCI user declaration is malformed")
			}
		}
	}
	uid, resolvedUser, err := resolveGuestUID(parts[0])
	if err != nil {
		return nil, err
	}
	if uid == 0 {
		return nil, fmt.Errorf("OCI user resolves to prohibited root identity")
	}
	gid := uid
	if resolvedUser != nil {
		gid, err = parseGuestID(resolvedUser.Gid)
		if err != nil {
			return nil, fmt.Errorf("OCI user primary group: %w", err)
		}
	}
	if len(parts) == 2 {
		gid, err = resolveGuestGID(parts[1])
		if err != nil {
			return nil, err
		}
	}
	if gid == 0 {
		return nil, fmt.Errorf("OCI group resolves to prohibited root identity")
	}
	groups := make([]uint32, 0)
	if resolvedUser != nil {
		groupIDs, lookupErr := resolvedUser.GroupIds()
		if lookupErr != nil {
			return nil, fmt.Errorf("OCI user supplementary groups: %w", lookupErr)
		}
		for _, raw := range groupIDs {
			groupID, parseErr := parseGuestID(raw)
			if parseErr != nil || groupID == 0 {
				return nil, fmt.Errorf("OCI user has an invalid or prohibited supplementary group")
			}
			groups = append(groups, groupID)
		}
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}, nil
}

func resolveGuestUID(value string) (uint32, *userdb.User, error) {
	if numeric, err := strconv.ParseUint(value, 10, 32); err == nil {
		if numeric >= uint64(^uint32(0)) {
			return 0, nil, fmt.Errorf("OCI user UID is outside the supported range")
		}
		if numeric == 0 {
			return 0, nil, nil
		}
		resolved, lookupErr := userdb.LookupId(strconv.FormatUint(numeric, 10))
		if lookupErr != nil {
			return uint32(numeric), nil, nil
		}
		return uint32(numeric), resolved, nil
	}
	resolved, err := userdb.Lookup(value)
	if err != nil {
		return 0, nil, fmt.Errorf("OCI user %q cannot be resolved: %w", value, err)
	}
	uid, err := parseGuestID(resolved.Uid)
	if err != nil {
		return 0, nil, fmt.Errorf("OCI user %q has an invalid UID", value)
	}
	return uid, resolved, nil
}

func resolveGuestGID(value string) (uint32, error) {
	if numeric, err := parseGuestID(value); err == nil {
		return numeric, nil
	}
	resolved, err := userdb.LookupGroup(value)
	if err != nil {
		return 0, fmt.Errorf("OCI group %q cannot be resolved: %w", value, err)
	}
	gid, err := parseGuestID(resolved.Gid)
	if err != nil {
		return 0, fmt.Errorf("OCI group %q has an invalid GID", value)
	}
	return gid, nil
}

func parseGuestID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 || parsed >= uint64(^uint32(0)) {
		return 0, fmt.Errorf("identity %q is outside the supported non-root range", value)
	}
	return uint32(parsed), nil
}

func mergeGuestEnvironment(environment []string, overrides ...string) []string {
	values := make(map[string]string, len(environment)+len(overrides))
	for _, entry := range append(append([]string(nil), environment...), overrides...) {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key != "" {
			values[key] = value
		}
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func guestWorkloadCommand(argv []string, supervised bool) []string {
	result := append([]string(nil), argv...)
	if !supervised {
		return result
	}
	return append([]string{guestSupervisorBinary, "--", guestInitBinary, "--policy", guestPolicyFile, "--"}, result...)
}

func guestExecCommand(argv []string, supervised bool) []string {
	result := append([]string(nil), argv...)
	if !supervised {
		return result
	}
	return append([]string{guestInitBinary, "--policy", guestPolicyFile, "--"}, result...)
}

func guestShellCommand(argv []string, noLoginShell bool) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("exec argv is empty")
	}
	shell := ""
	for _, candidate := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh"} {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			shell = candidate
			break
		}
	}
	if shell == "" {
		return nil, fmt.Errorf("sandbox image does not provide an executable shell at /bin/bash, /usr/bin/bash, or /bin/sh")
	}
	return guestShellCommandWithPath(shell, argv, noLoginShell), nil
}

func guestShellCommandWithPath(shell string, argv []string, noLoginShell bool) []string {
	mode := "-lc"
	if noLoginShell {
		mode = "-c"
	}
	quoted := make([]string, len(argv))
	for index, arg := range argv {
		quoted[index] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return []string{shell, mode, strings.Join(quoted, " ")}
}

func guestWorkdir(path string) string {
	if path == "" {
		return "/workspace"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "/workspace"
	}
	return path
}

func writeResponse(writer io.Writer, response Response) error {
	if response.Version == 0 {
		response.Version = ProtocolVersion
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return WriteFrame(writer, encoded)
}
