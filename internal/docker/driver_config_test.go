package docker

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParseDockerSandboxDriverConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantSet bool
		wantErr bool
	}{
		{name: "omitted", input: "", wantSet: false},
		{name: "empty object", input: `{}`, wantSet: false},
		{name: "CDI devices", input: `{"cdi_devices":["nvidia.com/gpu=0","vendor/device=1"]}`, want: []string{"nvidia.com/gpu=0", "vendor/device=1"}, wantSet: true},
		{name: "empty mounts", input: `{"mounts":[]}`, wantSet: false},
		{name: "empty CDI devices", input: `{"cdi_devices":[]}`, wantErr: true},
		{name: "null CDI devices", input: `{"cdi_devices":null}`, wantErr: true},
		{name: "empty CDI entry", input: `{"cdi_devices":[" "]}`, wantErr: true},
		{name: "non-array CDI", input: `{"cdi_devices":"device"}`, wantErr: true},
		{name: "null mounts", input: `{"mounts":null}`, wantErr: true},
		{name: "bind disabled by default", input: `{"mounts":[{"type":"bind","source":"/tmp","target":"/scratch"}]}`, wantErr: true},
		{name: "tmpfs mount", input: `{"mounts":[{"type":"tmpfs","target":"/scratch","size_bytes":4096,"mode":448,"options":["noexec","size=8m"]}]}`},
		{name: "volume mount", input: `{"mounts":[{"type":"volume","source":"cache","target":"/cache","subpath":"pkg"}]}`},
		{name: "unknown field", input: `{"unknown":true}`, wantErr: true},
		{name: "duplicate field", input: `{"cdi_devices":["a"],"cdi_devices":["b"]}`, wantErr: true},
		{name: "nested duplicate field", input: `{"mounts":[{"type":"tmpfs","target":"/a","target":"/b"}]}`, wantErr: true},
		{name: "not object", input: `[]`, wantErr: true},
		{name: "malformed JSON", input: `{"cdi_devices":[`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, has, _, _, err := parseDockerSandboxDriverConfig(tt.input, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if has != tt.wantSet || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parse = %#v, %v; want %#v, %v", got, has, tt.want, tt.wantSet)
			}
		})
	}
}

func TestValidateDriverConfigAllowedUsesOperatorGate(t *testing.T) {
	for _, test := range []struct {
		name     string
		input    string
		allowed  bool
		wantErr  bool
		wantUsed bool
	}{
		{name: "omitted"},
		{name: "empty object", input: `{}`},
		{name: "empty object whitespace", input: `{  }`},
		{name: "caller config disabled", input: `{"mounts":[]}`, wantErr: true},
		{name: "caller config enabled", input: `{"mounts":[]}`, allowed: true, wantUsed: true},
		{name: "non-object", input: `[]`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			used, err := validateDriverConfigAllowed(test.input, test.allowed)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate error=%v wantErr=%t", err, test.wantErr)
			}
			if err == nil && used != test.wantUsed {
				t.Fatalf("configUsed=%t for input %q", used, test.input)
			}
		})
	}
}

func TestDockerMountValidationSecurityCorpus(t *testing.T) {
	validBind := t.TempDir()
	if err := os.WriteFile(filepath.Join(validBind, "marker"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		mount      string
		binds      bool
		wantErr    bool
		wantSuffix string
	}{
		{name: "bind read only relabel shared", mount: `{"type":"bind","source":` + strconv.Quote(validBind) + `,"target":"/data","read_only":true,"selinux_label":"shared"}`, binds: true, wantSuffix: ":/data:ro,z"},
		{name: "bind private relabel", mount: `{"type":"bind","source":` + strconv.Quote(validBind) + `,"target":"/data","selinux_label":"private"}`, binds: true, wantSuffix: ":/data:ro,Z"},
		{name: "bind disabled", mount: `{"type":"bind","source":` + strconv.Quote(validBind) + `,"target":"/data"}`, wantErr: true},
		{name: "relative bind source", mount: `{"type":"bind","source":"relative","target":"/data"}`, binds: true, wantErr: true},
		{name: "missing bind source", mount: `{"type":"bind","source":"/missing/cautem-source","target":"/data"}`, binds: true, wantErr: true},
		{name: "invalid SELinux label", mount: `{"type":"bind","source":` + strconv.Quote(validBind) + `,"target":"/data","selinux_label":"relabel-all"}`, binds: true, wantErr: true},
		{name: "root target", mount: `{"type":"volume","source":"cache","target":"/"}`, wantErr: true},
		{name: "relative target", mount: `{"type":"volume","source":"cache","target":"data"}`, wantErr: true},
		{name: "traversal target", mount: `{"type":"volume","source":"cache","target":"/safe/../etc"}`, wantErr: true},
		{name: "protected target", mount: `{"type":"volume","source":"cache","target":"/run/openshell/credentials"}`, wantErr: true},
		{name: "protected target parent", mount: `{"type":"volume","source":"cache","target":"/opt/openshell-cache"}`},
		{name: "empty volume source", mount: `{"type":"volume","source":"","target":"/cache"}`, wantErr: true},
		{name: "absolute volume subpath", mount: `{"type":"volume","source":"cache","target":"/cache","subpath":"/etc"}`, wantErr: true},
		{name: "traversal volume subpath", mount: `{"type":"volume","source":"cache","target":"/cache","subpath":"pkg/../secret"}`, wantErr: true},
		{name: "space in volume subpath", mount: `{"type":"volume","source":"cache","target":"/cache","subpath":"package cache"}`, wantErr: true},
		{name: "tmpfs negative size", mount: `{"type":"tmpfs","target":"/tmpfs","size_bytes":-1}`, wantErr: true},
		{name: "tmpfs negative mode", mount: `{"type":"tmpfs","target":"/tmpfs","mode":-1}`, wantErr: true},
		{name: "tmpfs empty option", mount: `{"type":"tmpfs","target":"/tmpfs","options":[""]}`, wantErr: true},
		{name: "tmpfs malformed option", mount: `{"type":"tmpfs","target":"/tmpfs","options":["=value"]}`, wantErr: true},
		{name: "image mount unsupported", mount: `{"type":"image","source":"payload","target":"/payload"}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"mounts":[` + tc.mount + `]}`
			_, _, engineMounts, binds, err := parseDockerSandboxDriverConfig(input, tc.binds)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parse error=%v wantErr=%v", err, tc.wantErr)
			}
			if err != nil || tc.wantSuffix == "" {
				return
			}
			if len(binds) != 1 || !strings.HasSuffix(binds[0], tc.wantSuffix) || len(engineMounts) != 0 {
				t.Fatalf("bind result=%v engine mounts=%+v", binds, engineMounts)
			}
		})
	}

	if _, _, _, _, err := parseDockerSandboxDriverConfig(`{"mounts":[{"type":"tmpfs","target":"/one"},{"type":"volume","source":"cache","target":"/one"}]}`, false); err == nil {
		t.Fatal("duplicate mount target accepted")
	}
}
