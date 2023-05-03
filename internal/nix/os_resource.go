//go:generate go build -o testdata/mock_nix_copy_bin/nix testdata/mock_nix_copy.go

package nix

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

// currentProfileSymlinkPath is the location of the symlink pointing to the
// current system profile on nixos systems.
const currentProfileSymlinkPath = "/run/current-system"

// Ensure the implementation satisfies the expected interfaces.
var _ resource.ResourceWithValidateConfig = osResource{}

// osResource is the resource implementation.
type osResource struct{}

// Metadata returns the resource type name.
func (osResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os"
}

// Schema defines the schema for the resource.
func (osResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// TODO: support reboot on apply

	// TODO: support remote builds

	resp.Schema = schema.Schema{
		Description: "Manage a NixOS installation.",
		Attributes: map[string]schema.Attribute{
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Time at which the system profile as last updated.",
			},

			"profile_path": schema.StringAttribute{
				Required:    true,
				Description: "Store path of the system profile.",
			},

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
		},
	}
}

// osResourceModel maps the resource schema data.
type osResourceModel struct {
	LastUpdated types.String `tfsdk:"last_updated"`

	ProfilePath types.String `tfsdk:"profile_path"`

	User           types.String `tfsdk:"user"`
	Host           types.String `tfsdk:"host"`
	Port           types.Int64  `tfsdk:"port"`
	PublicKey      types.String `tfsdk:"public_key"`
	PrivateKeyPath types.String `tfsdk:"private_key_path"`
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

// sshClient returns an ssh client based on the ssh connection options in this
// model. If an error is encountered, it will be added to diagnostics and nil
// will be returned.
func (m osResourceModel) sshClient(diagnostics *diag.Diagnostics) *ssh.Client {
	pub := parsePublicKey(m.PublicKey.ValueString(), diagnostics)
	if pub == nil {
		return nil
	}

	priv := parsePrivateKey(m.PrivateKeyPath.ValueString(), diagnostics)
	if priv == nil {
		return nil
	}

	sshConfig := &ssh.ClientConfig{
		User: m.User.ValueString(),
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
	if !m.Port.IsNull() {
		port = m.Port.ValueInt64()
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", m.Host.ValueString(), port), sshConfig)
	if reportErrorWithTitle(err, "Could Not Establish SSH Connection", diagnostics) {
		return nil
	}

	return client
}

// copyAndActivate copies the ProfilePath of m to the remote host and activates
// it. If an error is encountered, it will be added to diagnostics. It returns
// whether any errors were encountered.
func (m osResourceModel) copyAndActivate(client *ssh.Client, diagnostics *diag.Diagnostics) bool {
	// TODO: it looks like the ssh used by `nix copy` is just based on path, so
	// we can potentially intercept the ssh connection stuff on the other side
	// of this and use this executable as the ssh binary (by creating temporary
	// symlinks and path entries, then checking os.Argv[0] on startup) to make
	// the ssh stuff as pure and deterministic as possible

	// Copy system profile closure
	remoteURI := fmt.Sprintf("ssh://%s@%s", m.User.ValueString(), m.Host.ValueString())
	cmd := exec.Command("nix", "--extra-experimental-features", "nix-command", "copy", "--to", remoteURI, m.ProfilePath.ValueString())
	envEntry := fmt.Sprintf("NIX_SSHOPTS=-p %d -i %s", m.Port.ValueInt64(), m.PrivateKeyPath.ValueString())
	cmd.Env = append(os.Environ(), envEntry)
	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		diagnostics.AddError(
			"Failed to Copy System Profile",
			fmt.Sprintf("%s, output:\n%s", err, combinedOutput),
		)
		return false
	}

	// Activate new system profile
	session := createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err = output(session, fmt.Sprintf("%s/bin/switch-to-configuration switch", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Switch System Profile", diagnostics) {
		return false
	}

	// Record profile switch
	session = createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err = output(session, fmt.Sprintf("nix-env -p /nix/var/nix/profiles/system --set %s", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Set System Profile", diagnostics) {
		return false
	}

	return true
}

// ValidateConfig performs custom config validation.
func (osResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Retrieve values from config
	var config osResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Host.IsUnknown() && !govalidator.IsHost(config.Host.ValueString()) {
		resp.Diagnostics.AddError("Invalid Host", "Host is not a valid IP address or hostname")
	}

	if !config.Port.IsUnknown() && !config.Port.IsNull() {
		port := config.Port.ValueInt64()
		if port <= 0 {
			resp.Diagnostics.AddError("Port Too Small", "Port was <= 0, expected positive, unsigned, 16-bit integer")
		} else if port > math.MaxUint16 {
			resp.Diagnostics.AddError("Port Too Large", "Port was > 65535, expected positive, unsigned, 16-bit integer")
		}
	}

	if !config.PublicKey.IsUnknown() {
		parsePublicKey(config.PublicKey.ValueString(), &resp.Diagnostics)
	}
	if !config.PrivateKeyPath.IsUnknown() {
		parsePrivateKey(config.PrivateKeyPath.ValueString(), &resp.Diagnostics)
	}
}

// statCurrentProfileSymlink runs stat -c %Y /run/current-system on the remote
// host and returns the mtime output and true if successful. If errors are
// encountered, they will be added to diagnostics and false is returned.
func statCurrentProfileSymlink(client *ssh.Client, diagnostics *diag.Diagnostics) (mtime time.Time, ok bool) {
	session := createSession(client, diagnostics)
	if session == nil {
		return time.Time{}, false
	}
	statOutput, err := output(session, "stat -c %Y "+currentProfileSymlinkPath)
	if reportErrorWithTitle(err, "Failed to Stat System Profile Path", diagnostics) {
		return time.Time{}, false
	}

	epoch, err := strconv.ParseInt(strings.TrimSuffix(string(statOutput), "\n"), 10, 64)
	if reportErrorWithTitle(err, "Failed to Parse Stat Output As Epoch Timestamp Integer", diagnostics) {
		return time.Time{}, false
	}

	return time.Unix(epoch, 0), true
}

// Create creates the resource and sets the initial Terraform state.
func (osResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// TODO: maybe support infecting non-nixos hosts, if the user explicitly
	// enables that behaviour (since this would be destructive, so we should
	// make them set an extra option to ensure they've understood what they're
	// doing). This should probably be done by go:embed'ding the script source,
	// copying it over via ssh, then executing it

	// Retrieve values from plan
	var plan osResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Establish ssh connection
	client := plan.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Activate the new profile
	if !plan.copyAndActivate(client, &resp.Diagnostics) {
		return
	}

	// Read last updated
	mtime, ok := statCurrentProfileSymlink(client, &resp.Diagnostics)
	if !ok {
		return
	}
	plan.LastUpdated = types.StringValue(mtime.Format(time.RFC850))

	// Set modified state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (osResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state osResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Establish ssh connection
	client := state.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Read current profile path from remote host
	session := createSession(client, &resp.Diagnostics)
	if session == nil {
		return
	}
	realpathOutput, err := output(session, "realpath "+currentProfileSymlinkPath)
	if reportErrorWithTitle(err, "Failed to Read System Profile Path", &resp.Diagnostics) {
		return
	}
	state.ProfilePath = types.StringValue(strings.TrimSuffix(string(realpathOutput), "\n"))

	// Read last updated
	mtime, ok := statCurrentProfileSymlink(client, &resp.Diagnostics)
	if !ok {
		return
	}
	state.LastUpdated = types.StringValue(mtime.Format(time.RFC850))

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (or osResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Just call Create, since Create and Update should behave identically
	createResp := &resource.CreateResponse{
		State:       resp.State,
		Private:     resp.Private,
		Diagnostics: resp.Diagnostics,
	}
	or.Create(ctx, resource.CreateRequest{
		Config:       req.Config,
		Plan:         req.Plan,
		ProviderMeta: req.ProviderMeta,
	}, createResp)
	*resp = resource.UpdateResponse{
		State:       createResp.State,
		Private:     createResp.Private,
		Diagnostics: createResp.Diagnostics,
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (osResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// We don't do anything to the remote system, because there isn't really
	// anything useful that we can do when an os resource is deleted
}
