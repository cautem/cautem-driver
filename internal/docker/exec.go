// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"golang.org/x/term"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-driver/internal/mounts"
)

// Exec runs a command in the container. With TTY, attaches stdin/stdout in raw mode.
// When the sandbox was created with cautem-init, argv is wrapped: cautem-init -- <cmd>.
//
// Docker ExecCreate Env replaces the process environment when non-empty.
// We always merge the container's Config.Env first so HTTP_PROXY / CA / HOME from
// create survive (otherwise `cautem exec` / create `-- agent` cannot reach the sidecar).
func (d *Driver) Exec(ctx context.Context, id core.ID, req driver.ExecRequest) (driver.ExecResult, error) {
	if len(req.Argv) == 0 {
		return driver.ExecResult{}, fmt.Errorf("docker exec: empty argv")
	}
	argv := req.Argv
	workdir := mounts.WorkdirInContainer
	if strings.TrimSpace(req.WorkDir) != "" {
		workdir = strings.TrimSpace(req.WorkDir)
	}
	var containerEnv []string
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec inspect container: %w", err)
	}
	if info.Container.Config == nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec: container config is unavailable")
	}
	{
		containerEnv = append([]string{}, info.Container.Config.Env...)
		if info.Container.Config.Labels[labelInit] == "1" {
			argv = append([]string{"/cautem/cautem-init", "--"}, req.Argv...)
		}
		// Proxy sidecar has no /workspace mount; exec must not chdir there.
		if info.Container.Config.Labels[labelRole] == roleProxy {
			workdir = "/"
		}
	}
	tty := req.TTY
	inFd := int(os.Stdin.Fd())
	outFd := int(os.Stdout.Fd())
	hostTTY := tty && term.IsTerminal(inFd)

	// Prefer stdout for size (same as docker CLI Out().GetTtySize).
	sizeFd := outFd
	if !term.IsTerminal(sizeFd) {
		sizeFd = inFd
	}

	var consoleSize client.ConsoleSize
	// Container env (proxy, CA, PATH) + caller overrides (credential placeholders).
	env := ensureTTYEnv(mergeEnv(containerEnv, req.Env))
	// Do not inject LINES/COLUMNS: Node TUIs prefer env over ioctl, and a wrong
	// pair permanently squashes the UI. Size comes from ConsoleSize + resize.
	if tty && (hostTTY || term.IsTerminal(sizeFd)) {
		if width, height, err := term.GetSize(sizeFd); err == nil && width > 0 && height > 0 {
			// Docker ConsoleSize is [height, width] (docker CLI fillConsoleSize).
			consoleSize = client.ConsoleSize{Height: uint(height), Width: uint(width)}
		}
	}

	execID, err := d.cli.ExecCreate(ctx, string(id), client.ExecCreateOptions{
		Cmd:          argv,
		Env:          env,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  tty,
		TTY:          tty,
		WorkingDir:   workdir,
		ConsoleSize:  consoleSize,
	})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec create: %w", err)
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{
		TTY:         tty,
		ConsoleSize: consoleSize,
	})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec attach: %w", err)
	}
	defer attach.Close()
	setConnNoDelay(attach.Conn)

	if tty {
		if hostTTY {
			old, err := term.MakeRaw(inFd)
			if err != nil {
				return driver.ExecResult{}, fmt.Errorf("docker exec raw terminal: %w", err)
			}
			defer func() { _ = term.Restore(inFd, old) }()
			// Resize before streaming so TUI mouse/scroll sees a real size on first paint.
			resizeExecOnce(ctx, d.cli, execID.ID, sizeFd)
			go resizeExecTTY(ctx, d.cli, execID.ID, sizeFd)
		}
		// When the remote PTY closes (e.g. shell `exit`), stop waiting on stdin —
		// otherwise stdin copy blocks until another keystroke.
		outDone := make(chan struct{})
		go func() {
			defer close(outDone)
			_, _ = io.Copy(os.Stdout, attach.Reader)
		}()
		go func() {
			// Small reads so mouse-wheel CSI sequences are forwarded promptly.
			_, _ = copyStdinTTY(attach.Conn, os.Stdin)
			_ = attach.CloseWrite()
		}()
		<-outDone
		_ = attach.CloseWrite()
	} else {
		_, _ = stdcopy.StdCopy(os.Stdout, os.Stderr, attach.Reader)
	}

	inspect, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec inspect: %w", err)
	}
	return driver.ExecResult{ExitCode: inspect.ExitCode}, nil
}

// ensureTTYEnv forces a guest TERM that Debian ships terminfo for.
// Host values like xterm-kitty / xterm-ghostty break mouse scroll inside the container.

// ensureTTYEnv forces a guest TERM that Debian ships terminfo for.
// Host values like xterm-kitty / xterm-ghostty break mouse scroll inside the container.
func ensureTTYEnv(base []string) []string {
	env := append([]string{}, base...)
	termName := strings.TrimSpace(os.Getenv("TERM"))
	switch {
	case termName == "" || termName == "dumb" || termName == "unknown":
		termName = "xterm-256color"
	case strings.Contains(termName, "kitty"),
		strings.Contains(termName, "ghostty"),
		strings.Contains(termName, "alacritty"),
		strings.HasPrefix(termName, "tmux"),
		strings.HasPrefix(termName, "screen"):
		// Keep 256color semantics; container rarely has fancy terminfo entries.
		termName = "xterm-256color"
	}
	env = mergeEnv(env, []string{"TERM=" + termName})
	if os.Getenv("COLORTERM") == "" {
		env = mergeEnv(env, []string{"COLORTERM=truecolor"})
	}
	return env
}

func setConnNoDelay(c net.Conn) {
	type noDelayer interface{ SetNoDelay(bool) error }
	if nd, ok := c.(noDelayer); ok {
		_ = nd.SetNoDelay(true)
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

// copyStdinTTY forwards host key/mouse bytes with a small buffer (not io.Copy's 32KiB).

// copyStdinTTY forwards host key/mouse bytes with a small buffer (not io.Copy's 32KiB).
func copyStdinTTY(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 256)
	var n int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, ew
			}
			if nr != nw {
				return n, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return n, nil
			}
			return n, er
		}
	}
}

func resizeExecOnce(ctx context.Context, cli *client.Client, execID string, inFd int) {
	width, height, err := term.GetSize(inFd)
	if err != nil || width <= 0 || height <= 0 {
		return
	}
	_, _ = cli.ExecResize(ctx, execID, client.ExecResizeOptions{
		Height: uint(height),
		Width:  uint(width),
	})
}

// Delete removes sandbox container, proxy sidecar, cautem network, and data volume.

// EnsureSSHDaemon starts cautem-sshd as root on the relay socket
// (idempotent: sshd exits when a live daemon already owns the socket) and
// waits until the socket exists. Returns driver.ErrSSHDisabled for sandboxes
// created without SSH.
func (d *Driver) EnsureSSHDaemon(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		return err
	}
	if info.Container.Config == nil || info.Container.Config.Labels[labelSSH] != "1" {
		return driver.ErrSSHDisabled
	}
	if info.Container.State == nil || !info.Container.State.Running {
		return fmt.Errorf("sandbox is not running")
	}
	sshSocket := d.sandboxSSHSocketPath()
	script := "exec " + defaults.GuestSSHD + " --socket " + shellQuote(sshSocket) + " >>" + defaults.GuestSSHLog + " 2>&1"
	execID, err := d.cli.ExecCreate(ctx, string(id), client.ExecCreateOptions{
		Cmd:        []string{"/bin/sh", "-c", script},
		User:       "0",
		WorkingDir: "/",
	})
	if err != nil {
		return fmt.Errorf("sshd exec create: %w", err)
	}
	if _, err := d.cli.ExecStart(ctx, execID.ID, client.ExecStartOptions{Detach: true}); err != nil {
		return fmt.Errorf("sshd exec start: %w", err)
	}
	deadline := time.Now().Add(readinessTimeout)
	for time.Now().Before(deadline) {
		if code, err := d.rawExec(ctx, string(id), []string{"test", "-S", sshSocket}); err == nil && code == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readinessPollInterval):
		}
	}
	return fmt.Errorf("sshd socket %s did not appear (see %s)", sshSocket, defaults.GuestSSHLog)
}

// rawExec runs argv as root without the cautem-init wrapper.

// rawExec runs argv as root without the cautem-init wrapper.
func (d *Driver) rawExec(ctx context.Context, id string, argv []string) (int, error) {
	execID, err := d.cli.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd:          argv,
		User:         "0",
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/",
	})
	if err != nil {
		return -1, err
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{})
	if err != nil {
		return -1, err
	}
	_, _ = io.Copy(io.Discard, attach.Reader)
	attach.Close()
	insp, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return -1, err
	}
	return insp.ExitCode, nil
}
