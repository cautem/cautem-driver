package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-driver/internal/vmguest"
)

const (
	defaultTerminalColumns = 80
	defaultTerminalRows    = 24
	terminalFrameChunk     = 32 << 10
	terminalOutputLimit    = 8 << 20
)

func (d *Driver) OpenExecTerminal(ctx context.Context, id core.ID, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: OpenExecTerminal requires a driver and context")
	}
	if len(request.Argv) == 0 {
		return nil, fmt.Errorf("vm terminal exec: argv is empty")
	}
	if request.Columns > 65535 || request.Rows > 65535 {
		return nil, fmt.Errorf("vm terminal exec: columns and rows must not exceed 65535")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return nil, err
	}
	if state.Status != "running" {
		return nil, fmt.Errorf("vm terminal exec: sandbox %q is %s", state.Name, state.Status)
	}
	d.mu.Lock()
	launchSpec, configured := d.launchSpecs[state.ID]
	d.mu.Unlock()
	if !configured {
		return nil, fmt.Errorf("vm terminal exec: workload spec is unavailable; restore it before opening a session")
	}
	workdir := strings.TrimSpace(request.WorkDir)
	if workdir == "" {
		workdir = launchSpec.WorkDir
	}
	if workdir == "" {
		workdir = "/workspace"
	}
	env, err := mergeLaunchEnvironment(launchSpec.Env, request.Env)
	if err != nil {
		return nil, err
	}
	if !hasEnvironmentKey(env, "TERM") {
		env = append(env, "TERM=xterm-256color")
		sort.Strings(env)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	columns, rows := request.Columns, request.Rows
	if columns == 0 {
		columns = defaultTerminalColumns
	}
	if rows == 0 {
		rows = defaultTerminalRows
	}
	connection, err := d.openControlStream(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec-terminal", Argv: append([]string(nil), request.Argv...), Env: env,
		WorkDir: workdir, User: launchSpec.User, NoLoginShell: request.NoLoginShell,
		Columns: columns, Rows: rows,
	})
	if err != nil {
		return nil, err
	}
	session := newVMExecTerminalSession(connection)
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.done:
		}
	}()
	return session, nil
}

func (d *Driver) execWithTerminal(ctx context.Context, id core.ID, request driver.ExecRequest) (driver.ExecResult, error) {
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv: request.Argv, Env: request.Env, WorkDir: request.WorkDir,
		NoLoginShell: request.NoLoginShell, Columns: defaultTerminalColumns, Rows: defaultTerminalRows,
	})
	if err != nil {
		return driver.ExecResult{}, err
	}
	defer session.Close()
	input := io.Reader(bytes.NewReader(request.Stdin))
	if request.StdinReader != nil {
		input = request.StdinReader
	}
	inputDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(session, input)
		if copyErr == nil {
			_, copyErr = session.Write([]byte{4})
		}
		inputDone <- copyErr
	}()
	var output ptyOutputBuffer
	buffer := make([]byte, terminalFrameChunk)
	for {
		count, readErr := session.Read(buffer)
		if count > 0 {
			output.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return driver.ExecResult{}, readErr
		}
	}
	code, err := session.Wait(ctx)
	if err != nil {
		return driver.ExecResult{}, err
	}
	return driver.ExecResult{ExitCode: code, Stdout: output.data, OutputTruncated: output.truncated}, nil
}

type ptyOutputBuffer struct {
	data      []byte
	truncated bool
}

func (buffer *ptyOutputBuffer) Write(payload []byte) {
	remaining := terminalOutputLimit - len(buffer.data)
	if remaining > len(payload) {
		remaining = len(payload)
	}
	if remaining > 0 {
		buffer.data = append(buffer.data, payload[:remaining]...)
	}
	if remaining < len(payload) {
		buffer.truncated = true
	}
}

func hasEnvironmentKey(env []string, want string) bool {
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && key == want {
			return true
		}
	}
	return false
}

func (d *Driver) openControlStream(ctx context.Context, id, socket string, request controlRequest) (net.Conn, error) {
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	for attempt := 0; attempt < 2; attempt++ {
		d.rotationMu.Lock()
		if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
			d.rotationMu.Unlock()
			return nil, err
		}
		token, err := readControlToken(sandboxDir)
		d.rotationMu.Unlock()
		if err != nil {
			return nil, err
		}
		request.AuthToken = token
		connection, err := writeControlStreamRequest(ctx, socket, request)
		if err == nil {
			return connection, nil
		}
		if !isGuestControlUnauthorized(err) || attempt != 0 || ctx.Err() != nil {
			return nil, err
		}
		d.rotationMu.Lock()
		err = d.completePendingControlTokenRotation(ctx, sandboxDir, socket)
		d.rotationMu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("VM terminal control authentication retry exhausted")
}

func writeControlStreamRequest(ctx context.Context, socket string, request controlRequest) (net.Conn, error) {
	var response controlResponse
	request.Version = vmguest.ProtocolVersion
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode VM terminal request: %w", err)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect VM guest terminal socket: %w", err)
	}
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopCancel:
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := vmguest.WriteFrame(connection, encoded); err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("write VM terminal request: %w", err)
	}
	answer, err := vmguest.ReadFrame(connection)
	if err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("read VM terminal handshake: %w", err)
	}
	if err := json.Unmarshal(answer, &response); err != nil {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("decode VM terminal handshake: %w", err)
	}
	if response.Version != vmguest.ProtocolVersion {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("unsupported VM terminal protocol response version %d", response.Version)
	}
	if response.Error != "" {
		close(stopCancel)
		_ = connection.Close()
		return nil, fmt.Errorf("guest control exec-terminal: %s", response.Error)
	}
	close(stopCancel)
	return connection, nil
}

type vmExecTerminalSession struct {
	connection net.Conn
	output     *io.PipeReader
	outputSink *io.PipeWriter
	done       chan struct{}
	writeMu    sync.Mutex
	stateMu    sync.Mutex
	exitCode   int
	readErr    error
	closeOnce  sync.Once
}

func newVMExecTerminalSession(connection net.Conn) *vmExecTerminalSession {
	reader, writer := io.Pipe()
	session := &vmExecTerminalSession{
		connection: connection, output: reader, outputSink: writer, done: make(chan struct{}),
	}
	go session.readFrames()
	return session
}

func (session *vmExecTerminalSession) Read(payload []byte) (int, error) {
	return session.output.Read(payload)
}

func (session *vmExecTerminalSession) Write(payload []byte) (int, error) {
	written := 0
	for len(payload) > 0 {
		count := len(payload)
		if count > terminalFrameChunk {
			count = terminalFrameChunk
		}
		if err := session.writeFrame(vmguest.TerminalFrame{Type: "stdin", Data: append([]byte(nil), payload[:count]...)}); err != nil {
			return written, err
		}
		written += count
		payload = payload[count:]
	}
	return written, nil
}

func (session *vmExecTerminalSession) Resize(ctx context.Context, columns, rows uint32) error {
	if ctx == nil {
		return fmt.Errorf("VM terminal resize context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if columns == 0 || rows == 0 || columns > 65535 || rows > 65535 {
		return fmt.Errorf("VM terminal dimensions must be between 1 and 65535")
	}
	return session.writeFrame(vmguest.TerminalFrame{Type: "resize", Columns: columns, Rows: rows})
}

func (session *vmExecTerminalSession) Wait(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("VM terminal wait context is nil")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-session.done:
	}
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	return session.exitCode, session.readErr
}

func (session *vmExecTerminalSession) Close() error {
	var closeErr error
	session.closeOnce.Do(func() {
		closeErr = session.connection.Close()
		_ = session.output.Close()
	})
	return closeErr
}

func (session *vmExecTerminalSession) writeFrame(frame vmguest.TerminalFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if err := vmguest.WriteFrame(session.connection, encoded); err != nil {
		return fmt.Errorf("write VM terminal frame: %w", err)
	}
	return nil
}

func (session *vmExecTerminalSession) readFrames() {
	var terminalErr error
	for {
		payload, err := vmguest.ReadFrame(session.connection)
		if err != nil {
			terminalErr = err
			break
		}
		var frame vmguest.TerminalFrame
		if err := json.Unmarshal(payload, &frame); err != nil {
			terminalErr = fmt.Errorf("decode VM terminal frame: %w", err)
			break
		}
		switch frame.Type {
		case "output":
			if len(frame.Data) == 0 {
				continue
			}
			if _, err := session.outputSink.Write(frame.Data); err != nil {
				terminalErr = err
				_ = session.connection.Close()
			}
		case "exit":
			session.stateMu.Lock()
			session.exitCode = frame.ExitCode
			session.stateMu.Unlock()
			terminalErr = nil
			goto finished
		default:
			terminalErr = fmt.Errorf("unexpected VM terminal frame type %q", frame.Type)
		}
		if terminalErr != nil {
			break
		}
	}

finished:
	session.stateMu.Lock()
	session.readErr = terminalErr
	session.stateMu.Unlock()
	if terminalErr != nil && !errors.Is(terminalErr, io.EOF) {
		_ = session.outputSink.CloseWithError(terminalErr)
	} else {
		_ = session.outputSink.Close()
	}
	close(session.done)
}
