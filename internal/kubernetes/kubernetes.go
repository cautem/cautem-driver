// Package kubernetes is an EXP Kubernetes compute-driver spike (not implemented).
package kubernetes

import (
	"context"
	"fmt"
	"io"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
)

// Driver is a placeholder for a future client-go / Agent Sandbox backend.
type Driver struct{}

// New returns the stub Kubernetes driver.
func New() *Driver { return &Driver{} }

func stub(op string) error {
	return fmt.Errorf("kubernetes driver: %s not implemented — see docs/exp/KUBERNETES.md", op)
}

func (d *Driver) Create(context.Context, driver.Spec) (driver.Handle, error) {
	return driver.Handle{}, stub("Create")
}
func (d *Driver) Start(context.Context, core.ID) error  { return stub("Start") }
func (d *Driver) Stop(context.Context, core.ID) error   { return stub("Stop") }
func (d *Driver) Delete(context.Context, core.ID) error { return stub("Delete") }
func (d *Driver) List(context.Context) ([]driver.Info, error) {
	return nil, stub("List")
}
func (d *Driver) Inspect(context.Context, string) (driver.Info, error) {
	return driver.Info{}, stub("Inspect")
}
func (d *Driver) Exec(context.Context, core.ID, driver.ExecRequest) (driver.ExecResult, error) {
	return driver.ExecResult{}, stub("Exec")
}
func (d *Driver) Logs(context.Context, core.ID, bool, io.Writer) error {
	return stub("Logs")
}
func (d *Driver) CopyTo(context.Context, core.ID, string, string) error {
	return stub("CopyTo")
}
func (d *Driver) CopyFrom(context.Context, core.ID, string, string) error {
	return stub("CopyFrom")
}
func (d *Driver) EnsureSSHDaemon(context.Context, core.ID) error {
	return stub("EnsureSSHDaemon")
}

var _ driver.ComputeDriver = (*Driver)(nil)
