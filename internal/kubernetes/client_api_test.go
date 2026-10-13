package kubernetes

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These cases port the Agent Sandbox API version probing behavior from the
// pinned OpenShell Kubernetes driver. The fake implements the typed API seam;
// these tests deliberately do not introduce an HTTP client or hand-written
// Kubernetes REST transport.
func TestOpenShellSandboxAPIVersionProbePrefersV1Beta1(t *testing.T) {
	fake := &fakeSandboxAPIClient{
		listErrors: map[string]error{
			sandboxAPIVersionV1Beta1:  nil,
			sandboxAPIVersionV1Alpha1: sandboxAPIStatusError{code: 404, message: "not installed"},
		},
	}

	version, err := detectSandboxAPIVersion(context.Background(), fake, "openshell")
	if err != nil {
		t.Fatalf("detectSandboxAPIVersion() error = %v", err)
	}
	if version != sandboxAPIVersionV1Beta1 {
		t.Fatalf("selected version = %q; want %q", version, sandboxAPIVersionV1Beta1)
	}
	assertSandboxAPIListCalls(t, fake.calls, []sandboxAPIListCall{{
		version:   sandboxAPIVersionV1Beta1,
		namespace: "openshell",
		limit:     1,
	}})
}

func TestOpenShellSandboxAPIVersionProbeFallsBackOnNotFound(t *testing.T) {
	fake := &fakeSandboxAPIClient{
		listErrors: map[string]error{
			sandboxAPIVersionV1Beta1:  sandboxAPIStatusError{code: 404, message: "could not find the requested resource"},
			sandboxAPIVersionV1Alpha1: nil,
		},
	}

	version, err := detectSandboxAPIVersion(context.Background(), fake, "team-a")
	if err != nil {
		t.Fatalf("detectSandboxAPIVersion() error = %v", err)
	}
	if version != sandboxAPIVersionV1Alpha1 {
		t.Fatalf("selected version = %q; want %q", version, sandboxAPIVersionV1Alpha1)
	}
	assertSandboxAPIListCalls(t, fake.calls, []sandboxAPIListCall{
		{version: sandboxAPIVersionV1Beta1, namespace: "team-a", limit: 1},
		{version: sandboxAPIVersionV1Alpha1, namespace: "team-a", limit: 1},
	})
}

func TestOpenShellSandboxAPIVersionProbeKeepsNonNotFoundErrors(t *testing.T) {
	for _, statusCode := range []int{401, 403, 500} {
		t.Run(strconv.Itoa(statusCode), func(t *testing.T) {
			fake := &fakeSandboxAPIClient{
				listErrors: map[string]error{
					sandboxAPIVersionV1Beta1:  sandboxAPIStatusError{code: statusCode, message: "probe failed"},
					sandboxAPIVersionV1Alpha1: nil,
				},
			}

			version, err := detectSandboxAPIVersion(context.Background(), fake, "openshell")
			if err == nil || version != "" {
				t.Fatalf("detectSandboxAPIVersion() = (%q, %v); want an error without a selected version", version, err)
			}
			if !strings.Contains(err.Error(), "probe failed") {
				t.Fatalf("error = %v; want original API error", err)
			}
			assertSandboxAPIListCalls(t, fake.calls, []sandboxAPIListCall{{
				version:   sandboxAPIVersionV1Beta1,
				namespace: "openshell",
				limit:     1,
			}})
		})
	}
}

func TestOpenShellSandboxAPIVersionProbeReportsMissingCRD(t *testing.T) {
	fake := &fakeSandboxAPIClient{
		listErrors: map[string]error{
			sandboxAPIVersionV1Beta1:  sandboxAPIStatusError{code: 404, message: "not found"},
			sandboxAPIVersionV1Alpha1: sandboxAPIStatusError{code: 404, message: "not found"},
		},
	}

	version, err := detectSandboxAPIVersion(context.Background(), fake, "openshell")
	if err == nil || version != "" {
		t.Fatalf("detectSandboxAPIVersion() = (%q, %v); want missing-CRD error", version, err)
	}
	if !strings.Contains(err.Error(), sandboxAPIVersionV1Beta1) || !strings.Contains(err.Error(), sandboxAPIVersionV1Alpha1) {
		t.Fatalf("error = %v; want both probed versions", err)
	}
	assertSandboxAPIListCalls(t, fake.calls, []sandboxAPIListCall{
		{version: sandboxAPIVersionV1Beta1, namespace: "openshell", limit: 1},
		{version: sandboxAPIVersionV1Alpha1, namespace: "openshell", limit: 1},
	})
}

func TestOpenShellSandboxAPIVersionProbeHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeSandboxAPIClient{}

	_, err := detectSandboxAPIVersion(ctx, fake, "openshell")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("detectSandboxAPIVersion() error = %v; want context.Canceled", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("API calls = %#v; want no call after cancellation", fake.calls)
	}
}

func TestOpenShellSandboxAPIVersionResolverCachesSuccessfulProbe(t *testing.T) {
	resolver := &sandboxAPIVersionResolver{}
	fake := &fakeSandboxAPIClient{}

	first, err := resolver.Resolve(context.Background(), fake, "openshell")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	secondClient := &fakeSandboxAPIClient{
		listErrors: map[string]error{
			sandboxAPIVersionV1Beta1: sandboxAPIStatusError{code: 403, message: "must not be called after cache hit"},
		},
	}
	second, err := resolver.Resolve(context.Background(), secondClient, "another-namespace")
	if err != nil {
		t.Fatalf("cached Resolve() error = %v", err)
	}
	if first != sandboxAPIVersionV1Beta1 || second != first {
		t.Fatalf("resolved versions = %q then %q; want cached %q", first, second, sandboxAPIVersionV1Beta1)
	}
	if len(fake.calls) != 1 || len(secondClient.calls) != 0 {
		t.Fatalf("calls = first:%d second:%d; want only initial probe", len(fake.calls), len(secondClient.calls))
	}
}

func TestOpenShellSandboxAPIVersionResolverDoesNotCacheFailures(t *testing.T) {
	resolver := &sandboxAPIVersionResolver{}
	fake := &fakeSandboxAPIClient{
		listErrors: map[string]error{
			sandboxAPIVersionV1Beta1: sandboxAPIStatusError{code: 403, message: "forbidden"},
		},
	}
	if _, err := resolver.Resolve(context.Background(), fake, "openshell"); err == nil {
		t.Fatal("first Resolve() should preserve the API error")
	}
	fake.listErrors[sandboxAPIVersionV1Beta1] = nil

	version, err := resolver.Resolve(context.Background(), fake, "openshell")
	if err != nil {
		t.Fatalf("second Resolve() error = %v; want retry after transient failure", err)
	}
	if version != sandboxAPIVersionV1Beta1 || len(fake.calls) != 2 {
		t.Fatalf("version/call count = %q/%d; want beta and two probes", version, len(fake.calls))
	}
}

func TestOpenShellSandboxOperatingStateUsesVersionSpecificFields(t *testing.T) {
	tests := []struct {
		name    string
		version string
		running bool
		want    map[string]any
	}{
		{name: "v1beta1 start", version: sandboxAPIVersionV1Beta1, running: true, want: map[string]any{"operatingMode": "Running"}},
		{name: "v1beta1 stop", version: sandboxAPIVersionV1Beta1, want: map[string]any{"operatingMode": "Suspended"}},
		{name: "v1alpha1 start", version: sandboxAPIVersionV1Alpha1, running: true, want: map[string]any{"replicas": 1}},
		{name: "v1alpha1 stop", version: sandboxAPIVersionV1Alpha1, want: map[string]any{"replicas": 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sandboxDesiredStateFields(tt.version, tt.running)
			if err != nil {
				t.Fatalf("sandboxDesiredStateFields() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("desired state fields = %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestOpenShellSandboxOperatingStateRejectsUnknownVersion(t *testing.T) {
	if _, err := sandboxDesiredStateFields("v9", true); err == nil {
		t.Fatal("sandboxDesiredStateFields(v9) should fail rather than assume the v1alpha1 schema")
	}
}

type sandboxAPIListCall struct {
	version   string
	namespace string
	limit     int
}

type fakeSandboxAPIClient struct {
	listErrors map[string]error
	calls      []sandboxAPIListCall
}

func (fake *fakeSandboxAPIClient) ListSandboxes(ctx context.Context, version, namespace string, limit int) error {
	fake.calls = append(fake.calls, sandboxAPIListCall{
		version:   version,
		namespace: namespace,
		limit:     limit,
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	if err, exists := fake.listErrors[version]; exists {
		return err
	}
	return nil
}

type sandboxAPIStatusError struct {
	code    int
	message string
}

func (err sandboxAPIStatusError) Error() string   { return err.message }
func (err sandboxAPIStatusError) StatusCode() int { return err.code }

func assertSandboxAPIListCalls(t *testing.T, got, want []sandboxAPIListCall) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListSandboxes calls = %#v; want %#v", got, want)
	}
}
