package nix

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"

	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
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
