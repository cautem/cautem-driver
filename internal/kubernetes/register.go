package kubernetes

import "github.com/cautem/cautem-driver/driver"

func init() {
	driver.Register("kubernetes", func() (driver.ComputeDriver, error) {
		return New(), nil
	})
}
