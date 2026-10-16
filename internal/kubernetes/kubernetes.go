// Package kubernetes implements the Kubernetes compute backend.
package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"k8s.io/client-go/dynamic"
)

// Driver accesses Agent Sandbox resources owned by one Gateway installation.
// Kubernetes credentials are loaded lazily so importing the driver does not
// make CLI startup depend on a cluster being reachable.
type Driver struct {
	gatewayID string

	mu            sync.Mutex
	client        dynamic.Interface
	loadClient    func() (dynamic.Interface, error)
	apiVersions   sandboxAPIVersionResolver
	runtimeConfig EngineConfig
	createBackend agentSandboxCreateSequenceBackend
}

// New returns a Kubernetes driver. Standalone users can set CAUTEM_GATEWAY_ID;
// the Gateway passes its durable identity through NewWithGatewayID.
func New() *Driver { return NewWithGatewayID(os.Getenv("CAUTEM_GATEWAY_ID")) }

// NewWithGatewayID scopes discovery to the durable identity of one Gateway.
func NewWithGatewayID(gatewayID string) *Driver {
	config := EngineConfigFromEnvironment()
	if strings.TrimSpace(gatewayID) != "" {
		config.GatewayID = strings.TrimSpace(gatewayID)
	}
	return NewWithEngineConfig(config)
}

func NewWithEngineConfig(config EngineConfig) *Driver {
	return &Driver{gatewayID: config.GatewayID, loadClient: loadDynamicKubernetesClient, runtimeConfig: config}
}

func NewWithConfig(values map[string]any) (*Driver, error) {
	config, err := EngineConfigFromMap(values)
	if err != nil {
		return nil, err
	}
	return NewWithEngineConfig(config), nil
}

func newWithClient(client dynamic.Interface, gatewayID string) *Driver {
	config := EngineConfigFromEnvironment()
	config.GatewayID = gatewayID
	return &Driver{gatewayID: gatewayID, client: client, runtimeConfig: config}
}

func (d *Driver) Create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	return d.create(ctx, spec)
}

// ValidateSpec rejects runtime controls that this backend cannot represent.
func (d *Driver) ValidateSpec(spec driver.Spec) error {
	if spec.PidsLimit != 0 {
		return fmt.Errorf("kubernetes compute driver does not support the Quarshell pids limit")
	}
	if len(spec.CDIDevices) > 0 {
		return fmt.Errorf("kubernetes compute driver does not support host CDI device IDs")
	}
	return nil
}

func (d *Driver) Start(ctx context.Context, id core.ID) error { return d.start(ctx, id) }
func (d *Driver) StartWithToken(ctx context.Context, id core.ID, token string) error {
	return d.startWithToken(ctx, id, token)
}

// UpdateSandboxPolicy replaces the immutable policy Secrets as one runtime generation.
func (d *Driver) UpdateSandboxPolicy(ctx context.Context, id core.ID, policy []byte) error {
	return d.updateSandboxPolicy(ctx, id, policy)
}
func (d *Driver) RefreshSandboxRuntimeCredentials(ctx context.Context, id core.ID) error {
	return d.refreshSandboxRuntimeCredentials(ctx, id)
}
func (d *Driver) Stop(ctx context.Context, id core.ID) error      { return d.stop(ctx, id) }
func (d *Driver) Delete(ctx context.Context, id core.ID) error    { return d.delete(ctx, id) }
func (d *Driver) List(ctx context.Context) ([]driver.Info, error) { return d.list(ctx) }
func (d *Driver) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	return d.inspect(ctx, nameOrID)
}

var _ driver.ComputeDriver = (*Driver)(nil)
var _ driver.TokenAwareStarter = (*Driver)(nil)
var _ driver.SandboxPolicyUpdater = (*Driver)(nil)
var _ driver.SandboxRuntimeCredentialRefresher = (*Driver)(nil)
