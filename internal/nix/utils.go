package nix

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"golang.org/x/crypto/ssh"
)

// reportErrorWithTitle adds an error whose title is the given value and whose
// detail is err.Error() if err is non-nil. It returns whether err is non-nil.
// It should usually be used ih the following way:
//
//	..., err := foo()
//	if reportErrorWithTitle(err, "Title", diagnostics) {
//		return
//	}
func reportErrorWithTitle(err error, title string, diagnostics *diag.Diagnostics) bool {
	if err == nil {
		return false
	}

	diagnostics.AddError(title, err.Error())
	return true
}

// mutexWriter wraps another writer and ensure that there are no two concurrent
// Write calls.
type mutexWriter struct {
	// mu protects w.
	mu sync.Mutex
	// w is the wrapped writer.
	w io.Writer
}

// Write implements io.Writer.
func (mw *mutexWriter) Write(p []byte) (n int, err error) {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	return mw.w.Write(p)
}

// combinedAndOutput reports the stdout, as well as the combined stdout and
// stderr resulting from the execution of cmd.
func combinedAndOutput(cmd *exec.Cmd) (output, combinedOutput []byte, err error) {
	var stdout, combined bytes.Buffer

	// This is necessary because cmd.Run only prevents concurrent writes to
	// Stdout and Stderr when Stdout == Stderr, which they won't in this case.
	mutexCombined := mutexWriter{w: &combined}

	cmd.Stdout = io.MultiWriter(&stdout, &mutexCombined)
	cmd.Stderr = &mutexCombined

	err = cmd.Run()
	return stdout.Bytes(), combined.Bytes(), err
}

// createSession creates a session from the given client. If an error is
// encountered, it will be added to diagnostics and nil will be returned.
func createSession(client *ssh.Client, diagnostics *diag.Diagnostics) *ssh.Session {
	session, err := client.NewSession()
	if reportErrorWithTitle(err, "Could Not Create SSH Session", diagnostics) {
		return nil
	}

	return session
}

// output executes cmd, returning the stdout if it succeeds, or an error message
// (containing the combined output, if it is non-empty) if the execution fails.
func output(session *ssh.Session, cmd string) ([]byte, error) {
	defer session.Close()

	var stdout, combined bytes.Buffer

	// This is necessary because cmd.Run only prevents concurrent writes to
	// Stdout and Stderr when Stdout == Stderr, which they won't in this case.
	mutexCombined := mutexWriter{w: &combined}

	session.Stdout = io.MultiWriter(&stdout, &mutexCombined)
	session.Stderr = &mutexCombined

	err := session.Run(cmd)
	if err != nil {
		if strings.TrimSpace(combined.String()) != "" {
			return nil, fmt.Errorf("%w, output:\n%s", err, combined.String())
		}

		return nil, err
	}

	return stdout.Bytes(), nil
}
