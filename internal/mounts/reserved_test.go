package mounts

import "testing"

func TestValidateContainerMountTarget(t *testing.T) {
	cases := []struct {
		target string
		ok     bool
	}{
		{"/workspace/src", true},
		{"/data", true},
		{"/cautem", false},
		{"/cautem/data", false},
		{"/cautem/policy.yaml", false},
		{"/proc", false},
		{"/sys/fs", false},
		{"/dev/null", false},
		{"/run/cautem/ssh.sock", false},
		{"/run", false},
		{"/etc/cautem", false},
		{"/var/run/cautem", false},
		{"relative", false},
		{"/workspace/../cautem", false}, // has ..
	}
	for _, tc := range cases {
		err := ValidateContainerMountTarget(tc.target)
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected err %v", tc.target, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: expected error", tc.target)
		}
	}
}

func TestValidateUploadDest(t *testing.T) {
	if err := ValidateUploadDest("/workspace/file.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUploadDest("/workspace"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUploadDest("/cautem/data/x"); err == nil {
		t.Fatal("expected refuse /cautem")
	}
}

func TestPathsOverlap(t *testing.T) {
	if !PathsOverlap("/cautem", "/cautem/data") {
		t.Fatal("expected overlap")
	}
	if PathsOverlap("/workspace", "/cautem") {
		t.Fatal("no overlap")
	}
}
