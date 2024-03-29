//go:generate go build -o testdata/mock_nix_copy_bin/nix testdata/mock_nix_copy.go

package nix

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

// currentSystemProfileSymlinkPath is the location of the symlink pointing to
// the current system profile on nixos systems.
const currentSystemProfileSymlinkPath = "/run/current-system"

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
				Description: "Time at which the system profile was last updated.",
			},

			"profile_path": schema.StringAttribute{
				Required:    true,
				Description: "Store path of the system profile.",
			},

			"ssh_conn": schema.SingleNestedAttribute{
				Attributes:  sshConnObjectAttrs,
				Required:    true,
				Description: "SSH connection options.",
			},
		},
	}
}

// osResourceModel maps the resource schema data.
type osResourceModel struct {
	LastUpdated types.String `tfsdk:"last_updated"`

	ProfilePath types.String `tfsdk:"profile_path"`

	SSHConn sshConnModel `tfsdk:"ssh_conn"`
}

// activate sets remote host's system profile to the specified profile path,
// assuming it has already been copied to that host's store. If an error is
// encountered, it will be added to diagnostics. It returns whether any errors
// were encountered.
func (m osResourceModel) activate(client *ssh.Client, diagnostics *diag.Diagnostics) bool {
	session := createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err := output(session, fmt.Sprintf("%s/bin/switch-to-configuration switch", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Switch System Profile", diagnostics) {
		return false
	}

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

	validateSSHConn(config.SSHConn, &resp.Diagnostics)
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
	client := plan.SSHConn.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Copy system profile closure
	if !plan.SSHConn.copyStorePath(plan.ProfilePath.ValueString(), &resp.Diagnostics) {
		return
	}

	// Activate the new profile
	if !plan.activate(client, &resp.Diagnostics) {
		return
	}

	// Read last updated
	mtime, ok := statRemoteSymlinks(client, []string{currentSystemProfileSymlinkPath}, &resp.Diagnostics)
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
	client := state.SSHConn.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Read current profile path from remote host
	session := createSession(client, &resp.Diagnostics)
	if session == nil {
		return
	}
	realpathOutput, err := output(session, "realpath "+currentSystemProfileSymlinkPath)
	if reportErrorWithTitle(err, "Failed to Read System Profile Path", &resp.Diagnostics) {
		return
	}
	state.ProfilePath = types.StringValue(strings.TrimSuffix(string(realpathOutput), "\n"))

	// Read last updated
	mtime, ok := statRemoteSymlinks(client, []string{currentSystemProfileSymlinkPath}, &resp.Diagnostics)
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
