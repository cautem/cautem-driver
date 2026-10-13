package kubernetes

import "github.com/cautem/cautem-driver/driver"

func init() {
	driver.Register("kubernetes", func() (driver.ComputeDriver, error) {
		return New(), nil
	})
	driver.RegisterEngine("kubernetes", func() (driver.Engine, error) {
		return New(), nil
	})
	driver.RegisterEngineWithConfig("kubernetes", func(config map[string]any) (driver.Engine, error) {
		return NewWithConfig(config)
	})
}
