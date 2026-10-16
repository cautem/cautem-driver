//go:build linux

package vm

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWorkerProcessAttributesRequirePrivateUserAndMountNamespaces(t *testing.T) {
	attributes := workerProcessAttributes()
	if attributes == nil {
		t.Fatal("worker process attributes are nil")
	}
	if attributes.Cloneflags&(unix.CLONE_NEWUSER|unix.CLONE_NEWNS) != unix.CLONE_NEWUSER|unix.CLONE_NEWNS {
		t.Fatalf("worker clone flags = %#x; want user and mount namespaces", attributes.Cloneflags)
	}
	if len(attributes.UidMappings) != 1 || attributes.UidMappings[0] != (syscall.SysProcIDMap{ContainerID: 0, HostID: os.Getuid(), Size: 1}) {
		t.Fatalf("worker UID mappings = %+v", attributes.UidMappings)
	}
	if len(attributes.GidMappings) != 1 || attributes.GidMappings[0] != (syscall.SysProcIDMap{ContainerID: 0, HostID: os.Getgid(), Size: 1}) {
		t.Fatalf("worker GID mappings = %+v", attributes.GidMappings)
	}
	if attributes.GidMappingsEnableSetgroups {
		t.Fatal("worker user namespace must deny setgroups")
	}
}

func TestPrepareWorkerIsolationFailsClosedWithoutNamespaceIdentity(t *testing.T) {
	if err := prepareWorkerIsolation(workerIsolationConfig{}); err == nil {
		t.Fatal("missing namespace identities unexpectedly accepted")
	}
}

func TestWorkerIsolationNamespaceSubprocess(t *testing.T) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("worker isolation probe requires a non-root host identity")
	}
	if os.Getenv("CAUTEM_VM_NAMESPACE_CHILD") == "1" {
		config := workerIsolationConfig{
			HostMountNamespace: os.Getenv("CAUTEM_VM_PARENT_MOUNT_NS"),
			HostUserNamespace:  os.Getenv("CAUTEM_VM_PARENT_USER_NS"),
		}
		if err := prepareWorkerIsolation(config); err != nil {
			t.Fatalf("prepare worker namespace: %v", err)
		}
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			t.Fatalf("worker namespace identity = %d:%d; want mapped namespace root", os.Geteuid(), os.Getegid())
		}
		return
	}

	parent, err := workerIsolationForChild()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWorkerIsolationNamespaceSubprocess$")
	command.Env = append(os.Environ(),
		"CAUTEM_VM_NAMESPACE_CHILD=1",
		"CAUTEM_VM_PARENT_MOUNT_NS="+parent.HostMountNamespace,
		"CAUTEM_VM_PARENT_USER_NS="+parent.HostUserNamespace,
	)
	command.SysProcAttr = workerProcessAttributes()
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, syscall.EPERM) || strings.Contains(strings.ToLower(err.Error()), "operation not permitted") || strings.Contains(strings.ToLower(string(output)), "operation not permitted") {
			t.Skipf("host blocks unprivileged user namespaces; live VM create must fail closed here: %v", err)
		}
		t.Fatalf("isolated worker subprocess failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "PASS") {
		t.Fatalf("isolated worker subprocess did not pass its probe: %s", output)
	}
}

func TestNamespaceIdentityRejectsUnexpectedValue(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "namespace")
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := namespaceIdentity(file.Name()); err == nil {
		t.Fatal("regular file unexpectedly accepted as a namespace identity")
	}
}
