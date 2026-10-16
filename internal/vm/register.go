package vm

import "github.com/cautem/quarshell-driver/driver"

func init() {
	driver.Register("vm", func() (driver.ComputeDriver, error) {
		return New(), nil
	})
}
