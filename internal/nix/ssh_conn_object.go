package nix

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"

	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// sshConnObjectAttrs defines the attributes for ssh connections.
var sshConnObjectAttrs = map[string]schema.Attribute{
	"user": schema.StringAttribute{
		Required:    true,
		Description: "SSH username to log in with. This user must have permission to change the system profile.",
	},
	"host": schema.StringAttribute{
		Required:    true,
		Description: "Hostname or IP address to connect to with SSH.",
	},
	"port": schema.Int64Attribute{
		Optional:            true,
		Description:         "Port to connect to with SSH. Defaults to 22.",
		MarkdownDescription: "Port to connect to with SSH. Defaults to `22`.",
	},
	"public_key": schema.StringAttribute{
		Required:            true,
		Description:         "The public key that the server will present, in the format used in authorized_keys files. Can be obtained using ssh-keyscan.",
		MarkdownDescription: "The public key that the server will present, in the format used in `authorized_keys` files. Can be obtained using `ssh-keyscan`.",
	},
	"private_key_path": schema.StringAttribute{
		Required:    true,
		Description: "SSH private key path to authenticate with.",
	},
}

// sshConnModel maps resource schema data.
type sshConnModel struct {
	User           types.String `tfsdk:"user"`
	Host           types.String `tfsdk:"host"`
	Port           types.Int64  `tfsdk:"port"`
	PublicKey      types.String `tfsdk:"public_key"`
	PrivateKeyPath types.String `tfsdk:"private_key_path"`
}

// sshClient returns an ssh client based on the ssh connection options in this
// model. If an error is encountered, it will be added to diagnostics and nil
// will be returned.
func (s sshConnModel) sshClient(diagnostics *diag.Diagnostics) *ssh.Client {
	pub := parsePublicKey(s.PublicKey.ValueString(), diagnostics)
	if pub == nil {
		return nil
	}

	priv := parsePrivateKey(s.PrivateKeyPath.ValueString(), diagnostics)
	if priv == nil {
		return nil
	}

	sshConfig := &ssh.ClientConfig{
		User: s.User.ValueString(),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(priv)},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			expected := pub.Marshal()
			actual := key.Marshal()
			if !bytes.Equal(expected, actual) {
				return fmt.Errorf("host key mismatch, expected: %s, got: %s",
					base64.StdEncoding.EncodeToString(expected),
					base64.StdEncoding.EncodeToString(actual),
				)
			}

			return nil
		}),
	}

	port := int64(22)
	if !s.Port.IsNull() {
		port = s.Port.ValueInt64()
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host.ValueString(), port), sshConfig)
	if reportErrorWithTitle(err, "Could Not Establish SSH Connection", diagnostics) {
		return nil
	}

	return client
}

// validateSSHConn validates the provided sshConn. If errors are encountered,
// they will be added to diagnostics.
func validateSSHConn(sshConn sshConnModel, diagnostics *diag.Diagnostics) {
	if !sshConn.Host.IsUnknown() && !govalidator.IsHost(sshConn.Host.ValueString()) {
		diagnostics.AddError("Invalid Host", "Host is not a valid IP address or hostname")
	}

	if !sshConn.Port.IsUnknown() && !sshConn.Port.IsNull() {
		port := sshConn.Port.ValueInt64()
		if port <= 0 {
			diagnostics.AddError("Port Too Small", "Port was <= 0, expected positive, unsigned, 16-bit integer")
		} else if port > math.MaxUint16 {
			diagnostics.AddError("Port Too Large", "Port was > 65535, expected positive, unsigned, 16-bit integer")
		}
	}

	if !sshConn.PublicKey.IsUnknown() {
		parsePublicKey(sshConn.PublicKey.ValueString(), diagnostics)
	}
	if !sshConn.PrivateKeyPath.IsUnknown() {
		parsePrivateKey(sshConn.PrivateKeyPath.ValueString(), diagnostics)
	}
}

// parsePublicKey parses publicKey, which should be in authorized_hosts format.
// If errors are encountered, they will be added to diagnostics and nil will
// be returned.
func parsePublicKey(publicKey string, diagnostics *diag.Diagnostics) ssh.PublicKey {
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if reportErrorWithTitle(err, "Could Not Parse SSH Public Key", diagnostics) {
		return nil
	}
	if len(rest) > 0 {
		diagnostics.AddError(
			"SSH Public Key Contained More Than One Entry",
			"SSH public key should only contain a single entry, but it contained more than one",
		)
		return nil
	}
	return pub
}

// parsePrivateKey parses the file at privateKeyPath, which should be in PEM
// format. If errors are encountered, they will be added to diagnostics and nil
// will be returned.
func parsePrivateKey(privateKeyPath string, diagnostics *diag.Diagnostics) ssh.Signer {
	buf, err := os.ReadFile(privateKeyPath)
	if reportErrorWithTitle(err, "Could Not Read SSH Private Key", diagnostics) {
		return nil
	}

	priv, err := ssh.ParsePrivateKey(buf)
	if reportErrorWithTitle(err, "Could Not Parse SSH Private Key", diagnostics) {
		return nil
	}
	return priv
}

// copyStorePath copies the specified path into the store of the host specified
// by this sshConnModel using `nix copy`.
func (s sshConnModel) copyStorePath(path string, diagnostics *diag.Diagnostics) bool {
	// TODO: it looks like the ssh used by `nix copy` is just based on path, so
	// we can potentially intercept the ssh connection stuff on the other side
	// of this and use this executable as the ssh binary (by creating temporary
	// symlinks and path entries, then checking os.Argv[0] on startup) to make
	// the ssh stuff as pure and deterministic as possible

	remoteURI := fmt.Sprintf("ssh://%s@%s", s.User.ValueString(), s.Host.ValueString())
	cmd := exec.Command("nix", "--extra-experimental-features", "nix-command", "copy", "--to", remoteURI, path)
	envEntry := "NIX_SSHOPTS=-o BatchMode=yes" // Disable interactive prompts.

	// Set remote port
	port := int64(22)
	if !s.Port.IsNull() {
		port = s.Port.ValueInt64()
	}

	envEntry += fmt.Sprintf(" -p %d", port)

	// Make sure we only allow the expected public key

	pub := parsePublicKey(s.PublicKey.ValueString(), diagnostics)
	if pub == nil {
		return false
	}

	line := knownhosts.Line([]string{fmt.Sprintf("%s:%d", s.Host.ValueString(), port)}, pub)

	tempKnownHosts, err := os.CreateTemp("", "known_hosts-")
	if err != nil {
		diagnostics.AddError(
			"Failed to Create Temporary Known Hosts File",
			err.Error(),
		)
		return false
	}
	defer func() {
		if err := os.Remove(tempKnownHosts.Name()); err != nil {
			diagnostics.AddWarning(
				"Failed to Remove Temporary Known Hosts File",
				err.Error(),
			)
		}
	}()
	if _, err := fmt.Fprint(tempKnownHosts, line); err != nil {
		_ = tempKnownHosts.Close()
		diagnostics.AddError(
			"Write Failed",
			err.Error(),
		)
		return false
	}
	_ = tempKnownHosts.Close()

	envEntry += fmt.Sprintf(" -o UserKnownHostsFile=%s", tempKnownHosts.Name())

	// Set private key
	envEntry += fmt.Sprintf(" -i %s", s.PrivateKeyPath.ValueString())

	// Execute command
	cmd.Env = append(os.Environ(), envEntry)
	if combinedOutput, err := cmd.CombinedOutput(); err != nil {
		diagnostics.AddError(
			"Copy Failed",
			fmt.Sprintf("%s, output:\n%s", err, combinedOutput),
		)
		return false
	}

	return true
}
