package docker

import (
	"fmt"

	"github.com/cautem/quarshell-driver/driver"
	"github.com/moby/moby/client"
)

func init() {
	driver.Register("docker", func() (driver.ComputeDriver, error) {
		return New()
	})
	driver.RegisterEngine("docker", func() (driver.Engine, error) {
		return New()
	})
	driver.RegisterEngineWithConfig("docker", func(values map[string]any) (driver.Engine, error) {
		cfg, socket, err := ConfigFromMap(values)
		if err != nil {
			return nil, err
		}
		var cli *client.Client
		if socket == "" {
			cli, err = client.New(client.FromEnv)
		} else {
			cli, err = client.New(client.FromEnv, client.WithHost(socket))
		}
		if err != nil {
			return nil, fmt.Errorf("docker driver: %w", err)
		}
		return NewFromClientWithRuntimeConfig(cli, cfg), nil
	})
}
