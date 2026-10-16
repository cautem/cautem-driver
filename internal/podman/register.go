package podman

import "github.com/cautem/quarshell-driver/driver"

func init() {
	driver.Register("podman", func() (driver.ComputeDriver, error) {
		return New()
	})
	driver.RegisterEngine("podman", func() (driver.Engine, error) {
		return New()
	})
	driver.RegisterEngineWithConfig("podman", func(values map[string]any) (driver.Engine, error) {
		cfg, err := ConfigFromMap(values)
		if err != nil {
			return nil, err
		}
		return NewWithConfig(cfg)
	})
}
