package kubernetes

import (
	"context"
	"fmt"
	"sort"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

const sandboxWatchServerTimeout = 5 * time.Minute

type agentSandboxWatchClient interface {
	ListSandboxObjects(ctx context.Context, version, namespace string) (*unstructured.UnstructuredList, error)
	WatchSandboxObjects(ctx context.Context, version, namespace, resourceVersion string) (watch.Interface, error)
}

// sandboxWatchUpdate is emitted only after a complete LIST or after one watch
// object has been applied to the local snapshot. A non-nil Snapshot replaces
// the consumer's entire view atomically; Object and Type describe one later
// watch event.
type sandboxWatchUpdate struct {
	Snapshot        []*unstructured.Unstructured
	Object          *unstructured.Unstructured
	Type            watch.EventType
	ResourceVersion string
}

type sandboxWatchBackoff struct {
	Initial time.Duration
	Maximum time.Duration
}

func (backoff sandboxWatchBackoff) delay(attempt int) time.Duration {
	if backoff.Initial <= 0 {
		return 0
	}
	delay := backoff.Initial
	maximum := backoff.Maximum
	if maximum <= 0 || maximum < delay {
		maximum = delay
	}
	for i := 0; i < attempt && delay < maximum; i++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

// runAgentSandboxWatch follows the Kubernetes list-then-watch contract used by
// OpenShell's kube-runtime watcher. Initial and recovery snapshots are emitted
// only after LIST succeeds in full. A compacted resourceVersion causes a fresh
// LIST; ordinary stream closure reconnects from the last observed version.
func runAgentSandboxWatch(
	ctx context.Context,
	client agentSandboxWatchClient,
	version, namespace string,
	backoff sandboxWatchBackoff,
	emit func(sandboxWatchUpdate) error,
) error {
	if ctx == nil {
		return fmt.Errorf("kubernetes watch context is nil")
	}
	if client == nil {
		return fmt.Errorf("agent Sandbox watch client is nil")
	}
	if emit == nil {
		return fmt.Errorf("agent Sandbox watch callback is nil")
	}
	if version != sandboxAPIVersionV1Beta1 && version != sandboxAPIVersionV1Alpha1 {
		return fmt.Errorf("unsupported Agent Sandbox API version %q", version)
	}

	var objects map[string]*unstructured.Unstructured
	resourceVersion := ""
	listBackoffAttempt := 0

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		listCtx, cancelList := context.WithTimeout(ctx, sandboxAPITimeout)
		list, err := client.ListSandboxObjects(listCtx, version, namespace)
		cancelList()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if isPermanentSandboxWatchAPIError(err) {
				return fmt.Errorf("list Agent Sandboxes for watch: %w", err)
			}
			if err := waitSandboxWatchBackoff(ctx, backoff.delay(listBackoffAttempt)); err != nil {
				return err
			}
			listBackoffAttempt++
			continue
		}

		listedObjects, listedResourceVersion, err := sandboxSnapshotFromList(list)
		if err != nil {
			return err
		}
		objects = listedObjects
		resourceVersion = listedResourceVersion
		listBackoffAttempt = 0
		if err := emit(sandboxWatchUpdate{
			Snapshot:        sortedSandboxSnapshot(objects),
			ResourceVersion: resourceVersion,
		}); err != nil {
			return err
		}

		watchBackoffAttempt := 0
		relist := false
		for !relist {
			if err := ctx.Err(); err != nil {
				return err
			}

			watcher, err := client.WatchSandboxObjects(ctx, version, namespace, resourceVersion)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if isSandboxWatchExpiredError(err) {
					if err := waitSandboxWatchBackoff(ctx, backoff.delay(watchBackoffAttempt)); err != nil {
						return err
					}
					relist = true
					continue
				}
				if isPermanentSandboxWatchAPIError(err) {
					return fmt.Errorf("watch Agent Sandboxes from resourceVersion %q: %w", resourceVersion, err)
				}
				if err := waitSandboxWatchBackoff(ctx, backoff.delay(watchBackoffAttempt)); err != nil {
					return err
				}
				watchBackoffAttempt++
				continue
			}
			if watcher == nil {
				if err := waitSandboxWatchBackoff(ctx, backoff.delay(watchBackoffAttempt)); err != nil {
					return err
				}
				watchBackoffAttempt++
				continue
			}

			watchErr, expired := consumeAgentSandboxWatch(ctx, watcher, objects, &resourceVersion, emit)
			watcher.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if watchErr != nil {
				return watchErr
			}
			if expired {
				if err := waitSandboxWatchBackoff(ctx, backoff.delay(watchBackoffAttempt)); err != nil {
					return err
				}
				watchBackoffAttempt++
				relist = true
				continue
			}
			if err := waitSandboxWatchBackoff(ctx, backoff.delay(watchBackoffAttempt)); err != nil {
				return err
			}
			watchBackoffAttempt++
		}
	}
}

func consumeAgentSandboxWatch(
	ctx context.Context,
	watcher watch.Interface,
	objects map[string]*unstructured.Unstructured,
	resourceVersion *string,
	emit func(sandboxWatchUpdate) error,
) (error, bool) {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err(), false
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil, false
			}
			switch event.Type {
			case watch.Bookmark:
				if object, ok := event.Object.(metav1.Object); ok && object.GetResourceVersion() != "" {
					*resourceVersion = object.GetResourceVersion()
				}
			case watch.Error:
				watchErr := sandboxWatchStatusError(event.Object)
				if isSandboxWatchExpiredError(watchErr) {
					return nil, true
				}
				if isPermanentSandboxWatchAPIError(watchErr) {
					return fmt.Errorf("agent Sandbox watch failed: %w", watchErr), false
				}
				return nil, false
			case watch.Added, watch.Modified, watch.Deleted:
				object, ok := event.Object.(*unstructured.Unstructured)
				if !ok || object == nil {
					return fmt.Errorf("agent Sandbox watch returned %s object of type %T", event.Type, event.Object), false
				}
				key, err := sandboxObjectKey(object)
				if err != nil {
					return err, false
				}
				if rv := object.GetResourceVersion(); rv != "" {
					*resourceVersion = rv
				}
				if event.Type == watch.Deleted {
					delete(objects, key)
				} else {
					objects[key] = object.DeepCopy()
				}
				if err := emit(sandboxWatchUpdate{
					Object:          object.DeepCopy(),
					Type:            event.Type,
					ResourceVersion: *resourceVersion,
				}); err != nil {
					return err, false
				}
			default:
				return fmt.Errorf("agent Sandbox watch returned unsupported event type %q", event.Type), false
			}
		}
	}
}

func sandboxSnapshotFromList(list *unstructured.UnstructuredList) (map[string]*unstructured.Unstructured, string, error) {
	if list == nil {
		return nil, "", fmt.Errorf("kubernetes Agent Sandbox LIST returned a nil snapshot")
	}
	resourceVersion := list.GetResourceVersion()
	if resourceVersion == "" {
		return nil, "", fmt.Errorf("kubernetes Agent Sandbox LIST returned an empty resourceVersion")
	}
	objects := make(map[string]*unstructured.Unstructured, len(list.Items))
	for i := range list.Items {
		object := &list.Items[i]
		key, err := sandboxObjectKey(object)
		if err != nil {
			return nil, "", fmt.Errorf("invalid Agent Sandbox LIST item %d: %w", i, err)
		}
		if _, exists := objects[key]; exists {
			return nil, "", fmt.Errorf("kubernetes Agent Sandbox LIST contains duplicate object %q", key)
		}
		objects[key] = object.DeepCopy()
	}
	return objects, resourceVersion, nil
}

func sandboxObjectKey(object metav1.Object) (string, error) {
	if object == nil || object.GetName() == "" {
		return "", fmt.Errorf("kubernetes Agent Sandbox object has no name")
	}
	return object.GetNamespace() + "/" + object.GetName(), nil
}

func sortedSandboxSnapshot(objects map[string]*unstructured.Unstructured) []*unstructured.Unstructured {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	snapshot := make([]*unstructured.Unstructured, 0, len(keys))
	for _, key := range keys {
		snapshot = append(snapshot, objects[key].DeepCopy())
	}
	return snapshot
}

func sandboxWatchStatusError(object runtime.Object) error {
	if object == nil {
		return fmt.Errorf("kubernetes watch returned an empty error status")
	}
	return apierrors.FromObject(object)
}

func isSandboxWatchExpiredError(err error) bool {
	return apierrors.IsResourceExpired(err) || apierrors.IsGone(err)
}

func isPermanentSandboxWatchAPIError(err error) bool {
	return apierrors.IsUnauthorized(err) ||
		apierrors.IsForbidden(err) ||
		apierrors.IsNotFound(err) ||
		apierrors.IsBadRequest(err) ||
		apierrors.IsInvalid(err)
}

func waitSandboxWatchBackoff(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ agentSandboxWatchClient = (*dynamicAgentSandboxAPIClient)(nil)
