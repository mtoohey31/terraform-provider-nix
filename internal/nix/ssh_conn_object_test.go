package nix

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mtoohey.com/terraform-provider-nix/internal/testutils/sshtest"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestOSResourceModel_sshClient(t *testing.T) {
	type summaryDetailPair struct {
		summary, detail string
	}

	ts := sshtest.NewKeyAuthServer(t)

	serverHost, serverPortString, ok := strings.Cut(ts.Addr.String(), ":")
	require.True(t, ok)
	serverPort, err := strconv.ParseInt(serverPortString, 10, 64)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	tempDir := t.TempDir()

	privateKeyPath := filepath.Join(tempDir, "client-ed25519")
	err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), 0o600)
	require.NoError(t, err)

	otherPubEd, otherPrivEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	otherPub, err := ssh.NewPublicKey(otherPubEd)
	require.NoError(t, err)

	otherPubString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherPub)))

	otherPrivBytes, err := x509.MarshalPKCS8PrivateKey(otherPrivEd)
	require.NoError(t, err)

	otherPrivateKeyPath := filepath.Join(tempDir, "other-ed25519")
	err = os.WriteFile(otherPrivateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: otherPrivBytes,
	}), 0o600)
	require.NoError(t, err)

	tests := []struct {
		description   string
		model         osResourceModel
		expectedError *summaryDetailPair
	}{
		{
			description: "happy path",
			model: osResourceModel{
				SSHConn: sshConnModel{
					Host:           types.StringValue(serverHost),
					Port:           types.Int64Value(serverPort),
					PublicKey:      types.StringValue(ts.PublicKeyString()),
					PrivateKeyPath: types.StringValue(privateKeyPath),
				},
			},
		},

		{
			description: "invalid public key",
			model: osResourceModel{
				SSHConn: sshConnModel{
					PublicKey: types.StringValue(""),
				},
			},
			expectedError: &summaryDetailPair{
				summary: "Could Not Parse SSH Public Key",
				detail:  "ssh: no key found",
			},
		},
		{
			description: "invalid private key",
			model: osResourceModel{
				SSHConn: sshConnModel{
					PublicKey:      types.StringValue(otherPubString),
					PrivateKeyPath: types.StringValue("non-existent"),
				},
			},
			expectedError: &summaryDetailPair{
				summary: "Could Not Read SSH Private Key",
				detail:  "open non-existent: no such file or directory",
			},
		},
		{
			description: "key mismatch",
			model: osResourceModel{
				SSHConn: sshConnModel{
					Host:           types.StringValue(serverHost),
					Port:           types.Int64Value(serverPort),
					PublicKey:      types.StringValue(otherPubString),
					PrivateKeyPath: types.StringValue(otherPrivateKeyPath),
				},
			},
			expectedError: &summaryDetailPair{
				summary: "Could Not Establish SSH Connection",
				detail: fmt.Sprintf(
					"ssh: handshake failed: host key mismatch, expected: %s, got: %s",
					strings.TrimPrefix(otherPubString, "ssh-ed25519 "),
					strings.TrimPrefix(ts.PublicKeyString(), "ssh-ed25519 "),
				),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			var expectedDiagnostics, actualDiagnostics diag.Diagnostics
			if test.expectedError != nil {
				expectedDiagnostics.AddError(test.expectedError.summary, test.expectedError.detail)
			}

			assert.Equal(t, test.expectedError == nil, test.model.SSHConn.sshClient(&actualDiagnostics) != nil)
			assert.Equal(t, expectedDiagnostics, actualDiagnostics)
		})
	}
}
