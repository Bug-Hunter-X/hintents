// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0


package main

import (
	"fmt"
	"os"

	"github.com/dotandev/hintents/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
