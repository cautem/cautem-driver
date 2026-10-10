package kubernetes

import (
	"context"
	"strings"
	"testing"

	"github.com/cautem/cautem-driver/driver"
)

func TestStubCreate(t *testing.T) {
	d := New()
	_, err := d.Create(context.Background(), driver.Spec{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "KUBERNETES") {
		t.Fatalf("err=%v", err)
	}
}
