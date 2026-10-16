//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-driver/internal/vmguest"
)

func main() {
	if err := vmguest.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
