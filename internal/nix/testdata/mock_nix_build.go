package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	expectedArgs := fmt.Sprintf("--extra-experimental-features nix-command build --no-link --print-out-paths %s", os.Getenv("MOCK_NIX_BUILD_EXPECTED_FLAKE_REF"))
	actualArgs := strings.Join(os.Args[1:], " ")
	if actualArgs != expectedArgs {
		panic(actualArgs)
	}

	fmt.Print(os.Getenv("MOCK_NIX_BUILD_STDOUT"))
	fmt.Fprintf(os.Stderr, os.Getenv("MOCK_NIX_BUILD_STDERR"))
	if exitCode := os.Getenv("MOCK_NIX_BUILD_EXIT_CODE"); exitCode != "" {
		ec, err := strconv.Atoi(exitCode)
		if err != nil {
			panic(err)
		}
		os.Exit(ec)
	}
}
