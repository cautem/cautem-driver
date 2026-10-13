package kubernetes

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

type sandboxWatchListResult struct {
	list *unstructured.UnstructuredList
	err  error
}

type sandboxWatchOpenResult struct {
	watch watch.Interface
	err   error
}

type scriptedSandboxWatchClient struct {
	mu sync.Mutex

	lists   []sandboxWatchListResult
	watches []sandboxWatchOpenResult

	listCalls int
	watchRVs  []string
	watchOpen chan string
}

func (client *scriptedSandboxWatchClient) ListSandboxObjects(context.Context, string, string) (*unstructured.UnstructuredList, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.listCalls++
	if len(client.lists) == 0 {
		return nil, errors.New("unexpected sandbox LIST")
	}
	result := client.lists[0]
	client.lists = client.lists[1:]
	return result.list, result.err
}

func (client *scriptedSandboxWatchClient) WatchSandboxObjects(ctx context.Context, _, _, resourceVersion string) (watch.Interface, error) {
	client.mu.Lock()
	client.watchRVs = append(client.watchRVs, resourceVersion)
	if len(client.watches) == 0 {
		client.mu.Unlock()
		return nil, errors.New("unexpected sandbox WATCH")
	}
	result := client.watches[0]
	client.watches = client.watches[1:]
	client.mu.Unlock()

	select {
	case client.watchOpen <- resourceVersion:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return result.watch, result.err
}

func TestOpenShellSandboxWatchDoesNotPublishFailedPartialList(t *testing.T) {
	watcher := watch.NewFake()
	client := &scriptedSandboxWatchClient{
		lists: []sandboxWatchListResult{
			{list: sandboxList("1", sandboxWatchObject("partial", "default", "1")), err: errors.New("temporary list failure")},
			{list: sandboxList("2", sandboxWatchObject("alpha", "default", "2"), sandboxWatchObject("beta", "default", "2"))},
		},
		watches:   []sandboxWatchOpenResult{{watch: watcher}},
		watchOpen: make(chan string, 4),
	}
	updates := make(chan sandboxWatchUpdate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := startSandboxWatch(ctx, client, updates)

	update := receiveSandboxWatchUpdate(t, updates)
	if update.Snapshot == nil {
		t.Fatalf("first watch update must be a complete snapshot: %#v", update)
	}
	if got, want := sandboxNames(update.Snapshot), []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("published snapshot = %v, want complete list %v", got, want)
	}
	if got := update.ResourceVersion; got != "2" {
		t.Fatalf("snapshot resourceVersion = %q, want 2", got)
	}
	if got := receiveSandboxWatchOpen(t, client); got != "2" {
		t.Fatalf("watch started from resourceVersion %q, want 2", got)
	}

	cancel()
	if err := receiveSandboxWatchResult(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatalf("watch result = %v, want context cancellation", err)
	}
}

func TestOpenShellSandboxWatchRelistsAfterExpiredResourceVersion(t *testing.T) {
	firstWatcher := watch.NewFake()
	secondWatcher := watch.NewFake()
	client := &scriptedSandboxWatchClient{
		lists: []sandboxWatchListResult{
			{list: sandboxList("10", sandboxWatchObject("alpha", "default", "10"))},
			{list: sandboxList("20", sandboxWatchObject("alpha", "default", "20"), sandboxWatchObject("beta", "default", "20"))},
		},
		watches: []sandboxWatchOpenResult{
			{watch: firstWatcher},
			{watch: secondWatcher},
		},
		watchOpen: make(chan string, 4),
	}
	updates := make(chan sandboxWatchUpdate, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := startSandboxWatch(ctx, client, updates)

	initial := receiveSandboxWatchUpdate(t, updates)
	if got, want := sandboxNames(initial.Snapshot), []string{"alpha"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("initial snapshot = %v, want %v", got, want)
	}
	if got := receiveSandboxWatchOpen(t, client); got != "10" {
		t.Fatalf("initial WATCH resourceVersion = %q, want 10", got)
	}

	firstWatcher.Modify(sandboxWatchObject("alpha", "default", "11"))
	modified := receiveSandboxWatchUpdate(t, updates)
	if modified.Type != watch.Modified || modified.Object.GetResourceVersion() != "11" {
		t.Fatalf("modified event = %#v", modified)
	}

	firstWatcher.Error(&metav1.Status{
		Status:  metav1.StatusFailure,
		Reason:  metav1.StatusReasonExpired,
		Message: "too old resource version",
		Code:    410,
	})
	recovered := receiveSandboxWatchUpdate(t, updates)
	if recovered.Snapshot == nil {
		t.Fatalf("expired watch must publish a replacement snapshot: %#v", recovered)
	}
	if got, want := sandboxNames(recovered.Snapshot), []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery snapshot = %v, want %v", got, want)
	}
	if recovered.ResourceVersion != "20" {
		t.Fatalf("recovery resourceVersion = %q, want 20", recovered.ResourceVersion)
	}
	if got := receiveSandboxWatchOpen(t, client); got != "20" {
		t.Fatalf("reconnected WATCH resourceVersion = %q, want 20", got)
	}

	cancel()
	if err := receiveSandboxWatchResult(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatalf("watch result = %v, want context cancellation", err)
	}
}

func TestOpenShellSandboxWatchReconnectsFromLastResourceVersionAfterClose(t *testing.T) {
	firstWatcher := watch.NewFake()
	secondWatcher := watch.NewFake()
	client := &scriptedSandboxWatchClient{
		lists: []sandboxWatchListResult{{list: sandboxList("42", sandboxWatchObject("alpha", "default", "42"))}},
		watches: []sandboxWatchOpenResult{
			{watch: firstWatcher},
			{watch: secondWatcher},
		},
		watchOpen: make(chan string, 4),
	}
	updates := make(chan sandboxWatchUpdate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := startSandboxWatch(ctx, client, updates)

	_ = receiveSandboxWatchUpdate(t, updates)
	if got := receiveSandboxWatchOpen(t, client); got != "42" {
		t.Fatalf("initial WATCH resourceVersion = %q, want 42", got)
	}
	firstWatcher.Stop()
	if got := receiveSandboxWatchOpen(t, client); got != "42" {
		t.Fatalf("reconnected WATCH resourceVersion = %q, want 42", got)
	}
	client.mu.Lock()
	listCalls := client.listCalls
	client.mu.Unlock()
	if listCalls != 1 {
		t.Fatalf("LIST calls after ordinary watch close = %d, want 1", listCalls)
	}

	cancel()
	if err := receiveSandboxWatchResult(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatalf("watch result = %v, want context cancellation", err)
	}
}

func TestSandboxWatchBackoffIsBoundedExponential(t *testing.T) {
	backoff := sandboxWatchBackoff{Initial: 100 * time.Millisecond, Maximum: 500 * time.Millisecond}
	got := []time.Duration{backoff.delay(0), backoff.delay(1), backoff.delay(2), backoff.delay(3), backoff.delay(8)}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 500 * time.Millisecond, 500 * time.Millisecond}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("backoff delays = %v, want %v", got, want)
	}
}

func startSandboxWatch(ctx context.Context, client *scriptedSandboxWatchClient, updates chan<- sandboxWatchUpdate) <-chan error {
	finished := make(chan error, 1)
	go func() {
		finished <- runAgentSandboxWatch(
			ctx,
			client,
			sandboxAPIVersionV1Beta1,
			"default",
			sandboxWatchBackoff{Initial: time.Millisecond, Maximum: time.Millisecond},
			func(update sandboxWatchUpdate) error {
				updates <- update
				return nil
			},
		)
	}()
	return finished
}

func receiveSandboxWatchUpdate(t *testing.T, updates <-chan sandboxWatchUpdate) sandboxWatchUpdate {
	t.Helper()
	select {
	case update := <-updates:
		return update
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sandbox watch update")
		return sandboxWatchUpdate{}
	}
}

func receiveSandboxWatchOpen(t *testing.T, client *scriptedSandboxWatchClient) string {
	t.Helper()
	select {
	case resourceVersion := <-client.watchOpen:
		return resourceVersion
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sandbox WATCH")
		return ""
	}
}

func receiveSandboxWatchResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sandbox watch loop to stop")
		return nil
	}
}

func sandboxList(resourceVersion string, objects ...*unstructured.Unstructured) *unstructured.UnstructuredList {
	list := &unstructured.UnstructuredList{}
	list.SetResourceVersion(resourceVersion)
	for _, object := range objects {
		list.Items = append(list.Items, *object.DeepCopy())
	}
	return list
}

func sandboxWatchObject(name, namespace, resourceVersion string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       namespace,
			"resourceVersion": resourceVersion,
		},
	}}
	return object
}

func sandboxNames(objects []*unstructured.Unstructured) []string {
	names := make([]string, 0, len(objects))
	for _, object := range objects {
		names = append(names, object.GetName())
	}
	return names
}
