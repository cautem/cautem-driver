package docker

import (
	"context"
	"fmt"
	"io"

	core "github.com/cautem/cautem-core"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// WaitMainProcess waits until the supervisor-managed sandbox container exits.
// Docker and Podman both report the canonical supervisor's exit status as the
// container exit status.
func (d *Driver) WaitMainProcess(ctx context.Context, id core.ID) (int, error) {
	wait := d.cli.ContainerWait(ctx, string(id), client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case result := <-wait.Result:
		if result.Error != nil {
			return int(result.StatusCode), fmt.Errorf("docker wait: %s", result.Error.Message)
		}
		return int(result.StatusCode), nil
	case err := <-wait.Error:
		if err != nil {
			return 0, fmt.Errorf("docker wait: %w", err)
		}
		return 0, fmt.Errorf("docker wait: engine closed the result channel")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// OpenMainProcessLogs attaches to sandbox output before the process wait starts.
// It intentionally excludes proxy sidecar logs so process completion closes
// this stream even when the sandbox's proxy remains alive.
func (d *Driver) OpenMainProcessLogs(ctx context.Context, id core.ID) (io.ReadCloser, error) {
	stream, err := d.cli.ContainerLogs(ctx, string(id), client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Follow: true, Tail: "500",
	})
	if err != nil {
		return nil, fmt.Errorf("docker attach main-process logs: %w", err)
	}
	reader, writer := io.Pipe()
	go func() {
		_, copyErr := stdcopy.StdCopy(writer, writer, stream)
		_ = stream.Close()
		_ = writer.CloseWithError(copyErr)
	}()
	return reader, nil
}

// OpenMainProcessTTY attaches to the container PTY after it has started. TTY
// output is a single unframed stream, and the connection carries stdin writes.
func (d *Driver) OpenMainProcessTTY(ctx context.Context, id core.ID, cols, rows uint32) (io.ReadWriteCloser, error) {
	if cols > 0 && rows > 0 {
		if err := d.ResizeMainProcessTTY(ctx, id, cols, rows); err != nil {
			return nil, fmt.Errorf("docker attach main-process TTY resize: %w", err)
		}
	}
	attached, err := d.cli.ContainerAttach(ctx, string(id), client.ContainerAttachOptions{
		Stream: true, Stdin: true, Stdout: true, Stderr: true, Logs: true,
	})
	if err != nil {
		return nil, fmt.Errorf("docker attach main-process TTY: %w", err)
	}
	return &mainProcessTTYConn{reader: attached.Reader, conn: attached.Conn}, nil
}

func (d *Driver) ResizeMainProcessTTY(ctx context.Context, id core.ID, cols, rows uint32) error {
	if cols == 0 || rows == 0 {
		return nil
	}
	_, err := d.cli.ContainerResize(ctx, string(id), client.ContainerResizeOptions{Width: uint(cols), Height: uint(rows)})
	if err != nil {
		return fmt.Errorf("docker resize main-process TTY: %w", err)
	}
	return nil
}

type mainProcessTTYConn struct {
	reader io.Reader
	conn   io.ReadWriteCloser
}

func (c *mainProcessTTYConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *mainProcessTTYConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *mainProcessTTYConn) Close() error                { return c.conn.Close() }

var _ interface {
	WaitMainProcess(context.Context, core.ID) (int, error)
} = (*Driver)(nil)

var _ interface {
	OpenMainProcessLogs(context.Context, core.ID) (io.ReadCloser, error)
} = (*Driver)(nil)

var _ interface {
	OpenMainProcessTTY(context.Context, core.ID, uint32, uint32) (io.ReadWriteCloser, error)
	ResizeMainProcessTTY(context.Context, core.ID, uint32, uint32) error
} = (*Driver)(nil)
