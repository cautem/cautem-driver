package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cautem/cautem-driver/driver"
	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/jsonmessage"
)

func (d *Driver) BuildImage(ctx context.Context, request driver.ImageBuildRequest) error {
	if d == nil || d.cli == nil {
		return fmt.Errorf("docker image build: client not initialized")
	}
	if request.Context == nil || strings.TrimSpace(request.Tag) == "" {
		return fmt.Errorf("docker image build: context and tag are required")
	}
	dockerfile := strings.TrimSpace(request.Dockerfile)
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	result, err := d.cli.ImageBuild(ctx, request.Context, client.ImageBuildOptions{
		Tags: []string{request.Tag}, Dockerfile: dockerfile, Remove: true, ForceRemove: true,
	})
	if err != nil {
		return fmt.Errorf("docker image build request: %w", err)
	}
	defer result.Body.Close()
	output := request.Output
	if output == nil {
		output = io.Discard
	}
	if err := jsonmessage.DisplayJSONMessagesStream(result.Body, output, 0, false, nil); err != nil {
		return fmt.Errorf("docker image build %s: %w", request.Tag, err)
	}
	return nil
}

var _ driver.ImageBuilder = (*Driver)(nil)
