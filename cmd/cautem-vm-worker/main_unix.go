//go:build darwin || linux

package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-driver/internal/vm"
)

func main() {
	if err := vm.RunWorkerFromStdin(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
