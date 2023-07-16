package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	expectedArgs := fmt.Sprintf("--extra-experimental-features nix-command copy --to ssh://test-user@%s /nix/store/test-profile-path",
		os.Getenv("MOCK_NIX_COPY_EXPECTED_HOST"))
	actualArgs := strings.Join(os.Args[1:], " ")
	if actualArgs != expectedArgs {
		panic(actualArgs)
	}

	expectedSSHPortOpt := fmt.Sprintf("-p %s",
		os.Getenv("MOCK_NIX_COPY_EXPECTED_PORT"))
	expectedSSHPrivateKeyOpt := fmt.Sprintf("-i %s",
		os.Getenv("MOCK_NIX_COPY_EXPECTED_PRIVATE_KEY_PATH"))
	actualSSHOpts := os.Getenv("NIX_SSHOPTS")
	if !strings.Contains(actualSSHOpts, expectedSSHPortOpt) ||
		!strings.Contains(actualSSHOpts, expectedSSHPrivateKeyOpt) {

		panic(actualSSHOpts)
	}

	fmt.Print(os.Getenv("MOCK_NIX_COPY_STDOUT"))
	fmt.Fprintf(os.Stderr, os.Getenv("MOCK_NIX_COPY_STDERR"))
	if exitCode := os.Getenv("MOCK_NIX_COPY_EXIT_CODE"); exitCode != "" {
		ec, err := strconv.Atoi(exitCode)
		if err != nil {
			panic(err)
		}
		os.Exit(ec)
	}
}
