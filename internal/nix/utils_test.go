package nix

import (
	"strconv"
	"testing"
	"time"

	"mtoohey.com/terraform-provider-nix/internal/testutils/sshtest"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestReportErrorWithTitle(t *testing.T) {
	assert.False(t, reportErrorWithTitle(nil, "", nil))

	actualDiagnostics := diag.Diagnostics{}
	assert.True(t, reportErrorWithTitle(assert.AnError, "Test Error Title", &actualDiagnostics))

	expectedDiagnostics := diag.Diagnostics{}
	expectedDiagnostics.AddError("Test Error Title", assert.AnError.Error())
	assert.Equal(t, expectedDiagnostics, actualDiagnostics)
}

func TestStatRemoteSymlinks(t *testing.T) {
	ts := sshtest.NewKeyAuthServer(t)

	priv, err := ssh.NewSignerFromKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	client, err := ssh.Dial("tcp", ts.Addr.String(), &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(priv)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)

	now := time.Now()

	tests := []struct {
		description string

		response1          sshtest.Response
		response2          *sshtest.Response
		expectedDiagnostic diag.Diagnostic
		expected           time.Time
	}{
		{
			description: "happy path",
			response1: sshtest.Response{
				Stdout: []byte(strconv.FormatInt(now.Unix(), 10)),
			},
			expected: now.Truncate(time.Second),
		},
		{
			description: "happy path, succeeds on second",
			response1:   sshtest.Response{Status: 1},
			response2: &sshtest.Response{
				Stdout: []byte(strconv.FormatInt(now.Unix(), 10)),
			},
			expected: now.Truncate(time.Second),
		},

		{
			description: "non-zero exit for both",
			response1:   sshtest.Response{Status: 1},
			response2:   &sshtest.Response{Status: 2},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Stat Remote Symlink",
				"Process exited with status 2",
			),
		},
		{
			description: "non-number output",
			response1:   sshtest.Response{Stdout: []byte("bogus")},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Parse Stat Output As Epoch Timestamp Integer",
				`strconv.ParseInt: parsing "bogus": invalid syntax`,
			),
		},
	}

	for _, test := range tests {
		execResponses := map[string][]sshtest.Response{
			"stat -c %Y test-symlink-path1": {test.response1},
		}
		if test.response2 != nil {
			execResponses["stat -c %Y test-symlink-path2"] = []sshtest.Response{*test.response2}
		}
		ts.Reset(execResponses)

		var actualDiagnostics diag.Diagnostics
		actual, actualOk := statRemoteSymlinks(client, []string{
			"test-symlink-path1",
			"test-symlink-path2",
		}, &actualDiagnostics)

		expectedRequests := []string{"stat -c %Y test-symlink-path1"}
		if test.response2 != nil {
			expectedRequests = append(expectedRequests, "stat -c %Y test-symlink-path2")
		}
		assert.Equal(t, expectedRequests, ts.Requests())
		if test.expectedDiagnostic == nil {
			assert.Empty(t, actualDiagnostics)
		} else {
			assert.Equal(t, diag.Diagnostics{test.expectedDiagnostic}, actualDiagnostics)
		}
		assert.Equal(t, test.expected, actual)
		assert.Equal(t, test.expectedDiagnostic == nil, actualOk)
	}
}
