package nix

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"mtoohey.com/terraform-provider-nix/internal/testutils/sshtest"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	testing_resource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestOSResourceModel_copyAndActivate(t *testing.T) {
	ts := sshtest.NewKeyAuthServer(t)

	priv, err := ssh.NewSignerFromKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	client, err := ssh.Dial("tcp", ts.Addr.String(), &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(priv)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Setenv("PATH", filepath.Join(wd, "testdata", "mock_nix_copy_bin"))

	tests := []struct {
		description string

		env           map[string]string
		execResponses map[string][]sshtest.Response

		expectedRequests   []string
		expectedDiagnostic diag.Diagnostic
	}{
		{
			description: "happy path",
			execResponses: map[string][]sshtest.Response{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch":            {{}},
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path": {{}},
			},
			expectedRequests: []string{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch",
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path",
			},
		},

		{
			description: "copy fails",
			env: map[string]string{
				"MOCK_NIX_COPY_STDOUT":    "something went wrong\n",
				"MOCK_NIX_COPY_STDERR":    "something went wrong\n",
				"MOCK_NIX_COPY_EXIT_CODE": "2",
			},
			expectedRequests: []string{},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Copy System Profile",
				"exit status 2, output:\nsomething went wrong\nsomething went wrong\n",
			),
		},
		{
			description: "switch fails",
			execResponses: map[string][]sshtest.Response{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch": {{
					Stdout: []byte("something went wrong\n"),
					Status: 2,
				}},
			},
			expectedRequests: []string{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch",
			},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Switch System Profile",
				"Process exited with status 2, output:\nsomething went wrong\n",
			),
		},
		{
			description: "set fails",
			execResponses: map[string][]sshtest.Response{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch": {{}},
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path": {{
					Stdout: []byte("something went wrong\n"),
					Status: 2,
				}},
			},
			expectedRequests: []string{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch",
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path",
			},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Set System Profile",
				"Process exited with status 2, output:\nsomething went wrong\n",
			),
		},
	}

	t.Setenv("MOCK_NIX_COPY_EXPECTED_HOST", "test-host")
	t.Setenv("MOCK_NIX_COPY_EXPECTED_PORT", "3152")
	t.Setenv("MOCK_NIX_COPY_EXPECTED_PRIVATE_KEY_PATH", "test/private/key/path")

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ts.Reset(test.execResponses)

			for k, v := range test.env {
				t.Setenv(k, v)
			}

			var actualDiagnostics diag.Diagnostics
			actualOk := osResourceModel{
				ProfilePath: types.StringValue("/nix/store/test-profile-path"),
				SSHConn: sshConnModel{
					User:           types.StringValue("test-user"),
					Host:           types.StringValue("test-host"),
					Port:           types.Int64Value(3152),
					PrivateKeyPath: types.StringValue("test/private/key/path"),
				},
			}.copyAndActivate(client, &actualDiagnostics)

			assert.Equal(t, test.expectedRequests, ts.Requests())
			assert.Equal(t, test.expectedDiagnostic == nil, actualOk)
			if test.expectedDiagnostic == nil {
				assert.Empty(t, actualDiagnostics)
			} else {
				assert.Equal(t, diag.Diagnostics{test.expectedDiagnostic}, actualDiagnostics)
			}
		})
	}
}

func TestOSResource_ValidateConfig(t *testing.T) {
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub, err := ssh.NewPublicKey(pubEd)
	require.NoError(t, err)

	pubString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	privBytes, err := x509.MarshalPKCS8PrivateKey(privEd)
	require.NoError(t, err)

	tempDir := t.TempDir()

	privateKeyPath := filepath.Join(tempDir, "client-ed25519")
	err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), 0o600)
	require.NoError(t, err)

	emptyPrivateKeyPath := filepath.Join(tempDir, "empty-ed25519")
	err = os.WriteFile(emptyPrivateKeyPath, nil, 0o600)
	require.NoError(t, err)

	testing_resource.Test(t, testing_resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []testing_resource.TestStep{
			// Invalid Host
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "***"
    public_key       = "%s"
    private_key_path = "%s"
  }
}`, pubString, privateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)Invalid Host.*Host is not a valid IP address or hostname`),
			},
			// Invalid Port, negative
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    port             = -1
    public_key       = "%s"
    private_key_path = "%s"
  }
}`, pubString, privateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)Port Too Small.*Port was <= 0, expected positive, unsigned, 16-bit integer`),
			},
			// Invalid Port, positive, too large
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    port             = 65536
    public_key       = "%s"
    private_key_path = "%s"
  }
}`, pubString, privateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)Port Too Large.*Port was > 65535, expected positive, unsigned, 16-bit integer`),
			},
			// Invalid PublicKey, not parseable
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    public_key       = "***"
    private_key_path = "%s"
  }
}`, privateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)Could Not Parse SSH Public Key.*ssh: no key found`),
			},
			// Invalid PublicKey, multiple entries
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    public_key       = "%s\n%[1]s"
    private_key_path = "%s"
  }
}`, pubString, privateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)SSH Public Key Contained More Than One Entry.*SSH public key should only contain a single entry, but it contained more than.*one`),
			},
			// Invalid PrivateKeyFile, missing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    public_key       = "%s"
    private_key_path = "bogus"
  }
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Could Not Read SSH Private Key.*open bogus: no such file or directory`),
			},
			// Invalid PrivateKeyFile, parse fails
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nix_os" "test" {
  profile_path = "/nix/store/test-profile-path"
  ssh_conn = {
    user             = "test-user"
    host             = "test-host"
    public_key       = "%s"
    private_key_path = "%s"
  }
}`, pubString, emptyPrivateKeyPath),
				ExpectError: regexp.MustCompile(`(?s)Could Not Parse SSH Private Key.*ssh: no key found`),
			},
		},
	})
}

func TestStatCurrentProfileSymlink(t *testing.T) {
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

		response           sshtest.Response
		expectedDiagnostic diag.Diagnostic
		expected           time.Time
	}{
		{
			description: "happy path",
			response: sshtest.Response{
				Stdout: []byte(strconv.FormatInt(now.Unix(), 10)),
			},
			expected: now.Truncate(time.Second),
		},

		{
			description: "non-zero exit",
			response:    sshtest.Response{Status: 1},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Stat System Profile Path",
				"Process exited with status 1",
			),
		},
		{
			description: "non-number output",
			response:    sshtest.Response{Stdout: []byte("bogus")},
			expectedDiagnostic: diag.NewErrorDiagnostic(
				"Failed to Parse Stat Output As Epoch Timestamp Integer",
				`strconv.ParseInt: parsing "bogus": invalid syntax`,
			),
		},
	}

	for _, test := range tests {
		ts.Reset(map[string][]sshtest.Response{
			"stat -c %Y /run/current-system": {test.response},
		})

		var actualDiagnostics diag.Diagnostics
		actual, actualOk := statCurrentSystemProfileSymlink(client, &actualDiagnostics)

		assert.Equal(t, []string{"stat -c %Y /run/current-system"}, ts.Requests())
		if test.expectedDiagnostic == nil {
			assert.Empty(t, actualDiagnostics)
		} else {
			assert.Equal(t, diag.Diagnostics{test.expectedDiagnostic}, actualDiagnostics)
		}
		assert.Equal(t, test.expected, actual)
		assert.Equal(t, test.expectedDiagnostic == nil, actualOk)
	}
}

func TestOSResource_Read(t *testing.T) {
	ts := sshtest.NewKeyAuthServer(t)

	serverHost, serverPortString, ok := strings.Cut(ts.Addr.String(), ":")
	require.True(t, ok)
	serverPort, err := strconv.ParseInt(serverPortString, 10, 64)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	privateKeyPath := filepath.Join(t.TempDir(), "client-ed25519")
	err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), 0o600)
	require.NoError(t, err)

	now := time.Now()

	var schemaResp resource.SchemaResponse
	osResource{}.Schema(nil, resource.SchemaRequest{}, &schemaResp)
	require.Empty(t, schemaResp.Diagnostics)

	tests := []struct {
		description string

		execResponses map[string][]sshtest.Response

		expectedRequests []string
		expectedResp     resource.ReadResponse
	}{
		{
			description: "happy path",
			execResponses: map[string][]sshtest.Response{
				"realpath /run/current-system":   {{Stdout: []byte("/nix/store/test-other-path\n")}},
				"stat -c %Y /run/current-system": {{Stdout: []byte(strconv.FormatInt(now.Unix(), 10))}},
			},
			expectedRequests: []string{
				"realpath /run/current-system",
				"stat -c %Y /run/current-system",
			},
			expectedResp: resource.ReadResponse{
				State: tfsdk.State{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"last_updated": tftypes.String,
							"profile_path": tftypes.String,
							"ssh_conn": tftypes.Object{
								AttributeTypes: map[string]tftypes.Type{
									"user":             tftypes.String,
									"host":             tftypes.String,
									"port":             tftypes.Number,
									"public_key":       tftypes.String,
									"private_key_path": tftypes.String,
								},
							},
						},
					}, map[string]tftypes.Value{
						"last_updated": tftypes.NewValue(tftypes.String, now.Format(time.RFC850)),
						"profile_path": tftypes.NewValue(tftypes.String, "/nix/store/test-other-path"),
						"ssh_conn": tftypes.NewValue(tftypes.Object{
							AttributeTypes: map[string]tftypes.Type{
								"user":             tftypes.String,
								"host":             tftypes.String,
								"port":             tftypes.Number,
								"public_key":       tftypes.String,
								"private_key_path": tftypes.String,
							},
						}, map[string]tftypes.Value{
							"user":             tftypes.NewValue(tftypes.String, "test-user"),
							"host":             tftypes.NewValue(tftypes.String, serverHost),
							"port":             tftypes.NewValue(tftypes.Number, serverPort),
							"public_key":       tftypes.NewValue(tftypes.String, ts.PublicKeyString()),
							"private_key_path": tftypes.NewValue(tftypes.String, privateKeyPath),
						}),
					}),
					Schema: schemaResp.Schema,
				},
			},
		},

		{
			description: "realpath fails",
			execResponses: map[string][]sshtest.Response{
				"realpath /run/current-system": {{
					Stdout: []byte("something went wrong\n"),
					Status: 2,
				}},
			},
			expectedRequests: []string{
				"realpath /run/current-system",
			},
			expectedResp: resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Failed to Read System Profile Path",
						"Process exited with status 2, output:\nsomething went wrong\n",
					),
				},
			},
		},
		{
			description: "stat fails",
			execResponses: map[string][]sshtest.Response{
				"realpath /run/current-system":   {{Stdout: []byte("/nix/store/test-other-path\n")}},
				"stat -c %Y /run/current-system": {{Stdout: []byte("bogus")}},
			},
			expectedRequests: []string{
				"realpath /run/current-system",
				"stat -c %Y /run/current-system",
			},
			expectedResp: resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Failed to Parse Stat Output As Epoch Timestamp Integer",
						"strconv.ParseInt: parsing \"bogus\": invalid syntax",
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ts.Reset(test.execResponses)

			actualResp := resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
			}

			osResource{}.Read(context.Background(), resource.ReadRequest{
				State: tfsdk.State{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"last_updated": tftypes.String,
							"profile_path": tftypes.String,
							"ssh_conn": tftypes.Object{
								AttributeTypes: map[string]tftypes.Type{
									"user":             tftypes.String,
									"host":             tftypes.String,
									"port":             tftypes.Number,
									"public_key":       tftypes.String,
									"private_key_path": tftypes.String,
								},
							},
						},
					}, map[string]tftypes.Value{
						"last_updated": tftypes.NewValue(tftypes.String, nil),
						"profile_path": tftypes.NewValue(tftypes.String, "/nix/store/test-profile-path"),
						"ssh_conn": tftypes.NewValue(tftypes.Object{
							AttributeTypes: map[string]tftypes.Type{
								"user":             tftypes.String,
								"host":             tftypes.String,
								"port":             tftypes.Number,
								"public_key":       tftypes.String,
								"private_key_path": tftypes.String,
							},
						}, map[string]tftypes.Value{
							"user":             tftypes.NewValue(tftypes.String, "test-user"),
							"host":             tftypes.NewValue(tftypes.String, serverHost),
							"port":             tftypes.NewValue(tftypes.Number, serverPort),
							"public_key":       tftypes.NewValue(tftypes.String, ts.PublicKeyString()),
							"private_key_path": tftypes.NewValue(tftypes.String, privateKeyPath),
						}),
					}),
					Schema: schemaResp.Schema,
				},
			}, &actualResp)

			assert.Equal(t, test.expectedRequests, ts.Requests())
			assert.Equal(t, test.expectedResp, actualResp)
		})
	}
}

func TestOSResource_Update(t *testing.T) {
	// This also tests Create since Update just forwards to Create

	ts := sshtest.NewKeyAuthServer(t)

	serverHost, serverPortString, ok := strings.Cut(ts.Addr.String(), ":")
	require.True(t, ok)
	serverPort, err := strconv.ParseInt(serverPortString, 10, 64)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	privateKeyPath := filepath.Join(t.TempDir(), "client-ed25519")
	err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), 0o600)
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Setenv("PATH", filepath.Join(wd, "testdata", "mock_nix_copy_bin"))

	now := time.Now()

	var schemaResp resource.SchemaResponse
	osResource{}.Schema(nil, resource.SchemaRequest{}, &schemaResp)
	require.Empty(t, schemaResp.Diagnostics)

	tests := []struct {
		description string

		env           map[string]string
		execResponses map[string][]sshtest.Response

		expectedRequests []string
		expectedResp     resource.UpdateResponse
	}{
		{
			description: "happy path",
			execResponses: map[string][]sshtest.Response{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch":            {{}},
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path": {{}},
				"stat -c %Y /run/current-system": {{
					Stdout: []byte(strconv.FormatInt(now.Unix(), 10)),
				}},
			},
			expectedRequests: []string{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch",
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path",
				"stat -c %Y /run/current-system",
			},
			expectedResp: resource.UpdateResponse{
				State: tfsdk.State{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"last_updated": tftypes.String,
							"profile_path": tftypes.String,
							"ssh_conn": tftypes.Object{
								AttributeTypes: map[string]tftypes.Type{
									"user":             tftypes.String,
									"host":             tftypes.String,
									"port":             tftypes.Number,
									"public_key":       tftypes.String,
									"private_key_path": tftypes.String,
								},
							},
						},
					}, map[string]tftypes.Value{
						"last_updated": tftypes.NewValue(tftypes.String, now.Format(time.RFC850)),
						"profile_path": tftypes.NewValue(tftypes.String, "/nix/store/test-profile-path"),
						"ssh_conn": tftypes.NewValue(tftypes.Object{
							AttributeTypes: map[string]tftypes.Type{
								"user":             tftypes.String,
								"host":             tftypes.String,
								"port":             tftypes.Number,
								"public_key":       tftypes.String,
								"private_key_path": tftypes.String,
							},
						}, map[string]tftypes.Value{
							"user":             tftypes.NewValue(tftypes.String, "test-user"),
							"host":             tftypes.NewValue(tftypes.String, serverHost),
							"port":             tftypes.NewValue(tftypes.Number, serverPort),
							"public_key":       tftypes.NewValue(tftypes.String, ts.PublicKeyString()),
							"private_key_path": tftypes.NewValue(tftypes.String, privateKeyPath),
						}),
					}),
					Schema: schemaResp.Schema,
				},
			},
		},

		{
			description: "copy fails",
			env: map[string]string{
				"MOCK_NIX_COPY_STDOUT":    "something went wrong\n",
				"MOCK_NIX_COPY_STDERR":    "something went wrong\n",
				"MOCK_NIX_COPY_EXIT_CODE": "2",
			},
			expectedRequests: []string{},
			expectedResp: resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Failed to Copy System Profile",
						"exit status 2, output:\nsomething went wrong\nsomething went wrong\n",
					),
				},
			},
		},
		{
			description: "stat fails",
			execResponses: map[string][]sshtest.Response{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch":            {{}},
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path": {{}},
				"stat -c %Y /run/current-system": {{
					Stdout: []byte("bogus"),
				}},
			},
			expectedRequests: []string{
				"/nix/store/test-profile-path/bin/switch-to-configuration switch",
				"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path",
				"stat -c %Y /run/current-system",
			},
			expectedResp: resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
				Diagnostics: diag.Diagnostics{
					diag.NewErrorDiagnostic(
						"Failed to Parse Stat Output As Epoch Timestamp Integer",
						"strconv.ParseInt: parsing \"bogus\": invalid syntax",
					),
				},
			},
		},
	}

	t.Setenv("MOCK_NIX_COPY_EXPECTED_HOST", serverHost)
	t.Setenv("MOCK_NIX_COPY_EXPECTED_PORT", serverPortString)
	t.Setenv("MOCK_NIX_COPY_EXPECTED_PRIVATE_KEY_PATH", privateKeyPath)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ts.Reset(test.execResponses)

			for k, v := range test.env {
				t.Setenv(k, v)
			}

			actualResp := resource.UpdateResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: schemaResp.Schema,
				},
			}

			osResource{}.Update(context.Background(), resource.UpdateRequest{
				Plan: tfsdk.Plan{
					Raw: tftypes.NewValue(tftypes.Object{
						AttributeTypes: map[string]tftypes.Type{
							"last_updated": tftypes.String,
							"profile_path": tftypes.String,
							"ssh_conn": tftypes.Object{
								AttributeTypes: map[string]tftypes.Type{
									"user":             tftypes.String,
									"host":             tftypes.String,
									"port":             tftypes.Number,
									"public_key":       tftypes.String,
									"private_key_path": tftypes.String,
								},
							},
						},
					}, map[string]tftypes.Value{
						"last_updated": tftypes.NewValue(tftypes.String, nil),
						"profile_path": tftypes.NewValue(tftypes.String, "/nix/store/test-profile-path"),
						"ssh_conn": tftypes.NewValue(tftypes.Object{
							AttributeTypes: map[string]tftypes.Type{
								"user":             tftypes.String,
								"host":             tftypes.String,
								"port":             tftypes.Number,
								"public_key":       tftypes.String,
								"private_key_path": tftypes.String,
							},
						}, map[string]tftypes.Value{
							"user":             tftypes.NewValue(tftypes.String, "test-user"),
							"host":             tftypes.NewValue(tftypes.String, serverHost),
							"port":             tftypes.NewValue(tftypes.Number, serverPort),
							"public_key":       tftypes.NewValue(tftypes.String, ts.PublicKeyString()),
							"private_key_path": tftypes.NewValue(tftypes.String, privateKeyPath),
						}),
					}),
					Schema: schemaResp.Schema,
				},
			}, &actualResp)

			assert.Equal(t, test.expectedRequests, ts.Requests())
			assert.Equal(t, test.expectedResp, actualResp)
		})
	}
}
