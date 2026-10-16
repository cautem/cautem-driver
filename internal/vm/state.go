package vm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const sandboxStateVersion = 1
const controlTokenRotationVersion = 1

const pendingControlTokenRotationName = "control.token.pending"

// sandboxState is deliberately limited to non-secret recovery metadata. In
// particular, sandbox environment variables and credentials must never be
// persisted in this file.
type sandboxState struct {
	Version                    int       `json:"version"`
	ID                         string    `json:"id"`
	Name                       string    `json:"name"`
	Image                      string    `json:"image,omitempty"`
	Rootfs                     string    `json:"rootfs,omitempty"`
	RootfsSourceType           string    `json:"rootfs_source_type,omitempty"`
	RootfsSourceRef            string    `json:"rootfs_source_ref,omitempty"`
	RootfsSourceDigest         string    `json:"rootfs_source_digest,omitempty"`
	RootfsSourceManifestDigest string    `json:"rootfs_source_manifest_digest,omitempty"`
	Platform                   string    `json:"platform,omitempty"`
	VCPUs                      uint8     `json:"vcpus,omitempty"`
	MemoryMiB                  uint32    `json:"memory_mib,omitempty"`
	Status                     string    `json:"status"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

func (s *stateStore) find(nameOrID string) (sandboxState, error) {
	if validSandboxID(nameOrID) {
		return s.load(nameOrID)
	}
	states, err := s.list()
	if err != nil {
		return sandboxState{}, err
	}
	for _, state := range states {
		if state.Name == nameOrID {
			return state, nil
		}
	}
	return sandboxState{}, fmt.Errorf("VM sandbox %q not found", nameOrID)
}

type stateStore struct{ root string }

func defaultStateDir() string {
	base, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Join(base, "cautem", "vm", "sandboxes")
}

func openStateStore(root string) (*stateStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("VM state directory is unset")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve VM state directory: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create VM state directory %q: %w", root, err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect VM state directory %q: %w", root, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("VM state path %q must be a real directory", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure VM state directory %q: %w", root, err)
	}
	return &stateStore{root: root}, nil
}

func newSandboxID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate VM sandbox ID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

// createControlToken creates a per-sandbox capability authorizing host control
// of the guest agent. It stays outside JSON state and in the private sandbox dir.
func createControlToken(sandboxDir string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate VM guest control token: %w", err)
	}
	token := hex.EncodeToString(raw[:])
	path := filepath.Join(sandboxDir, "control.token")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create VM guest control token: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("secure VM guest control token: %w", err)
	}
	if _, err := file.WriteString(token); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write VM guest control token: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync VM guest control token: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close VM guest control token: %w", err)
	}
	return token, nil
}

func readControlToken(sandboxDir string) (string, error) {
	path := filepath.Join(sandboxDir, "control.token")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect VM guest control token: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != 64 {
		return "", fmt.Errorf("VM guest control token must be a private 64-character regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read VM guest control token: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return "", fmt.Errorf("VM guest control token changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return "", fmt.Errorf("read VM guest control token: %w", err)
	}
	if len(data) != 64 {
		return "", fmt.Errorf("VM guest control token has invalid length")
	}
	if _, err := hex.DecodeString(string(data)); err != nil {
		return "", fmt.Errorf("VM guest control token is malformed")
	}
	return string(data), nil
}

type controlTokenRotation struct {
	Version    uint16 `json:"version"`
	RotationID string `json:"rotation_id"`
	NextToken  string `json:"next_token"`
}

func newControlTokenRotation() (controlTokenRotation, error) {
	var token [32]byte
	var id [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return controlTokenRotation{}, fmt.Errorf("generate next VM guest control token: %w", err)
	}
	if _, err := rand.Read(id[:]); err != nil {
		return controlTokenRotation{}, fmt.Errorf("generate VM guest control token rotation ID: %w", err)
	}
	return controlTokenRotation{
		Version: controlTokenRotationVersion, RotationID: hex.EncodeToString(id[:]),
		NextToken: hex.EncodeToString(token[:]),
	}, nil
}

func readPendingControlTokenRotation(sandboxDir string) (controlTokenRotation, bool, error) {
	path := filepath.Join(sandboxDir, pendingControlTokenRotationName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return controlTokenRotation{}, false, nil
	}
	if err != nil {
		return controlTokenRotation{}, false, fmt.Errorf("inspect pending VM control token rotation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 1024 {
		return controlTokenRotation{}, false, fmt.Errorf("pending VM control token rotation must be a private regular file under 1 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return controlTokenRotation{}, false, fmt.Errorf("read pending VM control token rotation: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return controlTokenRotation{}, false, fmt.Errorf("pending VM control token rotation changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1025))
	decoder.DisallowUnknownFields()
	var rotation controlTokenRotation
	if err := decoder.Decode(&rotation); err != nil {
		return controlTokenRotation{}, false, fmt.Errorf("decode pending VM control token rotation: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return controlTokenRotation{}, false, fmt.Errorf("pending VM control token rotation must contain one JSON object")
	}
	if rotation.Version != controlTokenRotationVersion || !validControlTokenHex(rotation.NextToken) || !validRotationIDHex(rotation.RotationID) {
		return controlTokenRotation{}, false, fmt.Errorf("pending VM control token rotation has an unsupported version or malformed values")
	}
	return rotation, true, nil
}

func writePendingControlTokenRotation(sandboxDir string, rotation controlTokenRotation) error {
	if rotation.Version != controlTokenRotationVersion || !validControlTokenHex(rotation.NextToken) || !validRotationIDHex(rotation.RotationID) {
		return fmt.Errorf("refusing to persist malformed VM control token rotation")
	}
	path := filepath.Join(sandboxDir, pendingControlTokenRotationName)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("pending VM control token rotation already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pending VM control token rotation path: %w", err)
	}
	encoded, err := json.Marshal(rotation)
	if err != nil {
		return fmt.Errorf("encode pending VM control token rotation: %w", err)
	}
	if err := writeAtomicPrivateFile(sandboxDir, path, ".control-token-pending-*", encoded); err != nil {
		return fmt.Errorf("persist pending VM control token rotation: %w", err)
	}
	return nil
}

func replaceControlToken(sandboxDir, token string) error {
	if !validControlTokenHex(token) {
		return fmt.Errorf("refusing to persist malformed VM guest control token")
	}
	path := filepath.Join(sandboxDir, "control.token")
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect VM guest control token before replacement: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("VM guest control token must remain a private regular file")
	}
	if err := writeAtomicPrivateFile(sandboxDir, path, ".control-token-*", []byte(token)); err != nil {
		return fmt.Errorf("replace VM guest control token: %w", err)
	}
	return nil
}

func writeAtomicPrivateFile(dir, destination, pattern string, contents []byte) error {
	temporary, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpPath := temporary.Name()
	defer os.Remove(tmpPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removePendingControlTokenRotation(sandboxDir string) error {
	path := filepath.Join(sandboxDir, pendingControlTokenRotationName)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending VM control token rotation: %w", err)
	}
	directory, err := os.Open(sandboxDir)
	if err != nil {
		return fmt.Errorf("open VM sandbox directory after token rotation: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync VM sandbox directory after token rotation: %w", err)
	}
	return nil
}

func validControlTokenHex(token string) bool {
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func validRotationIDHex(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func (s *stateStore) path(id string) (string, error) {
	if !validSandboxID(id) {
		return "", fmt.Errorf("invalid VM sandbox ID %q", id)
	}
	return filepath.Join(s.root, id+".json"), nil
}

func validSandboxID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (s *stateStore) save(state sandboxState) error {
	path, err := s.path(state.ID)
	if err != nil {
		return err
	}
	if err := validateStoredState(state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode VM sandbox state: %w", err)
	}
	temporary, err := os.CreateTemp(s.root, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary VM state: %w", err)
	}
	tmpPath := temporary.Name()
	defer os.Remove(tmpPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary VM state: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary VM state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary VM state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary VM state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish VM state %q: %w", state.ID, err)
	}
	directory, err := os.Open(s.root)
	if err != nil {
		return fmt.Errorf("open VM state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync VM state directory: %w", err)
	}
	return nil
}

func (s *stateStore) create(name, image string, now time.Time) (sandboxState, error) {
	states, err := s.list()
	if err != nil {
		return sandboxState{}, err
	}
	for _, existing := range states {
		if existing.Name == name {
			return sandboxState{}, fmt.Errorf("VM sandbox %q already exists", name)
		}
	}
	id, err := newSandboxID()
	if err != nil {
		return sandboxState{}, err
	}
	state := sandboxState{
		Version:   sandboxStateVersion,
		ID:        id,
		Name:      name,
		Image:     image,
		Status:    "created",
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
	}
	if err := s.save(state); err != nil {
		return sandboxState{}, err
	}
	return state, nil
}

func (s *stateStore) load(id string) (sandboxState, error) {
	path, err := s.path(id)
	if err != nil {
		return sandboxState{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return sandboxState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return sandboxState{}, fmt.Errorf("VM state %q is not a regular file", id)
	}
	file, err := os.Open(path)
	if err != nil {
		return sandboxState{}, fmt.Errorf("open VM state %q: %w", id, err)
	}
	defer file.Close()
	var state sandboxState
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return sandboxState{}, fmt.Errorf("decode VM state %q: %w", id, err)
	}
	if err := validateStoredState(state); err != nil {
		return sandboxState{}, fmt.Errorf("invalid VM state %q: %w", id, err)
	}
	if state.ID != id {
		return sandboxState{}, fmt.Errorf("VM state filename ID %q does not match stored ID %q", id, state.ID)
	}
	return state, nil
}

func (s *stateStore) list() ([]sandboxState, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("read VM state directory: %w", err)
	}
	states := make([]sandboxState, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		state, err := s.load(id)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].CreatedAt.Before(states[j].CreatedAt) })
	return states, nil
}

func (s *stateStore) delete(id string) error {
	path, err := s.path(id)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove VM state %q: %w", id, err)
	}
	return nil
}

func validateStoredState(state sandboxState) error {
	if state.Version != sandboxStateVersion {
		return fmt.Errorf("unsupported state version %d", state.Version)
	}
	if !validSandboxID(state.ID) {
		return fmt.Errorf("invalid sandbox ID")
	}
	if err := validateSandboxName(state.Name); err != nil {
		return err
	}
	if state.Status != "created" && state.Status != "running" && state.Status != "stopped" {
		return fmt.Errorf("invalid sandbox status %q", state.Status)
	}
	if state.CreatedAt.IsZero() || state.UpdatedAt.IsZero() || state.UpdatedAt.Before(state.CreatedAt) {
		return fmt.Errorf("invalid sandbox timestamps")
	}
	if err := validateRootfsProvenance(state); err != nil {
		return err
	}
	return nil
}

func validateRootfsProvenance(state sandboxState) error {
	if state.RootfsSourceType == "" {
		if state.RootfsSourceRef != "" || state.RootfsSourceDigest != "" || state.RootfsSourceManifestDigest != "" || state.Platform != "" {
			return fmt.Errorf("incomplete rootfs source provenance")
		}
		return nil
	}
	platform, err := v1.ParsePlatform(state.Platform)
	if err != nil || platform.OS != "linux" || (platform.Architecture != "amd64" && platform.Architecture != "arm64") {
		return fmt.Errorf("invalid rootfs source platform %q", state.Platform)
	}
	if _, err := v1.NewHash(state.RootfsSourceDigest); err != nil {
		return fmt.Errorf("invalid rootfs source digest: %w", err)
	}
	switch state.RootfsSourceType {
	case "tar":
		if state.RootfsSourceRef != "uploaded-tar" || state.RootfsSourceManifestDigest != "" {
			return fmt.Errorf("invalid uploaded rootfs provenance")
		}
	case "oci":
		if state.RootfsSourceRef == "" {
			return fmt.Errorf("OCI rootfs provenance is missing its reference")
		}
		if _, err := v1.NewHash(state.RootfsSourceManifestDigest); err != nil {
			return fmt.Errorf("invalid source manifest digest: %w", err)
		}
	default:
		return fmt.Errorf("unsupported rootfs source type %q", state.RootfsSourceType)
	}
	return nil
}
