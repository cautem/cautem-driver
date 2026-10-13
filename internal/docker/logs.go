// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	core "github.com/cautem/cautem-core"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// Logs streams stdout/stderr from the sandbox container and, when present, the
// egress proxy sidecar (where OCSF agent-observation events are emitted).
// When follow is true, starts from the last 500 lines per container.
func (d *Driver) Logs(ctx context.Context, id core.ID, follow bool, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	opts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Timestamps: false,
	}
	if follow {
		opts.Tail = "500"
	}

	type src struct {
		id     string
		prefix string
	}
	sources := []src{{id: string(id), prefix: "sandbox"}}

	if info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{}); err == nil && info.Container.Config != nil {
		name := info.Container.Config.Labels[labelName]
		if name == "" {
			name = strings.TrimPrefix(strings.TrimPrefix(info.Container.Name, "/"), "cautem-")
		}
		if name != "" {
			proxyName := "cautem-proxy-" + name
			if _, err := d.cli.ContainerInspect(ctx, proxyName, client.ContainerInspectOptions{}); err == nil {
				sources = append(sources, src{id: proxyName, prefix: "proxy"})
			}
		}
	}

	if len(sources) == 1 {
		rc, err := d.cli.ContainerLogs(ctx, sources[0].id, opts)
		if err != nil {
			return fmt.Errorf("docker logs: %w", err)
		}
		defer rc.Close()
		_, err = stdcopy.StdCopy(w, w, rc)
		return err
	}

	var mu sync.Mutex
	writeLine := func(prefix, text string) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := fmt.Fprintf(w, "[%s] %s\n", prefix, text)
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(sources))
	for _, s := range sources {
		rc, err := d.cli.ContainerLogs(ctx, s.id, opts)
		if err != nil {
			if s.prefix == "proxy" {
				continue
			}
			return fmt.Errorf("docker logs %s: %w", s.id, err)
		}
		wg.Add(1)
		go func(prefix string, rc io.ReadCloser) {
			defer wg.Done()
			defer rc.Close()
			pr, pw := io.Pipe()
			go func() {
				_, copyErr := stdcopy.StdCopy(pw, pw, rc)
				_ = pw.CloseWithError(copyErr)
			}()
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				if ctx.Err() != nil {
					errCh <- ctx.Err()
					return
				}
				if err := writeLine(prefix, sc.Text()); err != nil {
					errCh <- err
					return
				}
			}
			if err := sc.Err(); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}(s.prefix, rc)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
