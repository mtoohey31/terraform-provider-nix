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

// currentUserProfileSymlinkPaths is the location of the symlink pointing to
// the current user profile for home-manager environments.
var currentUserProfileSymlinkPaths = []string{
	`"${XDG_STATE_HOME:-$HOME/.local/state}/nix/profiles/home-manager"`,
	`"${NIX_STATE_DIR:-/nix/var/nix}/profiles/per-user/$USER/home-manager"`,
}

// Ensure the implementation satisfies the expected interfaces.
var _ resource.ResourceWithValidateConfig = hmEnvResource{}

// hmEnvResource is the resource implementation.
type hmEnvResource struct{}

// Metadata returns the resource type name.
func (hmEnvResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hm_env"
}

// Schema defines the schema for the resource.
func (hmEnvResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// TODO: support remote builds

	resp.Schema = schema.Schema{
		Description: "Manage a Home Manager environment.",
		Attributes: map[string]schema.Attribute{
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Time at which the user profile was last updated.",
			},

			"profile_path": schema.StringAttribute{
				Required:    true,
				Description: "Store path of the user profile.",
			},

			"ssh_conn": schema.SingleNestedAttribute{
				Attributes:  sshConnObjectAttrs,
				Required:    true,
				Description: "SSH connection options.",
			},
		},
	}
}

// hmEnvResourceModel maps the resource schema data.
type hmEnvResourceModel struct {
	LastUpdated types.String `tfsdk:"last_updated"`

	ProfilePath types.String `tfsdk:"profile_path"`

	SSHConn sshConnModel `tfsdk:"ssh_conn"`
}

// activate sets remote host's system profile to the specified profile path,
// assuming it has already been copied to that host's store. If an error is
// encountered, it will be added to diagnostics. It returns whether any errors
// were encountered.
func (m hmEnvResourceModel) activate(client *ssh.Client, diagnostics *diag.Diagnostics) bool {
	session := createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err := output(session, fmt.Sprintf("%s/activate", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Switch User Profile", diagnostics) {
		return false
	}

	return true
}

// ValidateConfig performs custom config validation.
func (hmEnvResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Retrieve values from config
	var config osResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	validateSSHConn(config.SSHConn, &resp.Diagnostics)
}

// Create creates the resource and sets the initial Terraform state.
func (hmEnvResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan hmEnvResourceModel
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

	// Copy user profile closure
	if !plan.SSHConn.copyStorePath(plan.ProfilePath.ValueString(), &resp.Diagnostics) {
		return
	}

	// Activate the new profile
	if !plan.activate(client, &resp.Diagnostics) {
		return
	}

	// Read last updated
	mtime, ok := statRemoteSymlinks(client, currentUserProfileSymlinkPaths, &resp.Diagnostics)
	if !ok {
		return
	}
	plan.LastUpdated = types.StringValue(mtime.Format(time.RFC850))

	// Set modified state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (hmEnvResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state hmEnvResourceModel
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
	var realpathOutput []byte
	paths := currentUserProfileSymlinkPaths
	for {
		session := createSession(client, &resp.Diagnostics)
		if session == nil {
			return
		}

		var err error
		realpathOutput, err = output(session, "realpath "+paths[0])

		if err == nil {
			break
		} // err != nil

		paths = paths[1:]
		if len(paths) == 0 {
			reportErrorWithTitle(err, "Failed to Read User Profile Path", &resp.Diagnostics)
			return
		}
	}
	state.ProfilePath = types.StringValue(strings.TrimSuffix(string(realpathOutput), "\n"))

	// Read last updated
	mtime, ok := statRemoteSymlinks(client, currentUserProfileSymlinkPaths, &resp.Diagnostics)
	if !ok {
		return
	}
	state.LastUpdated = types.StringValue(mtime.Format(time.RFC850))

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (or hmEnvResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
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
func (hmEnvResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// We don't do anything to the remote system, because there isn't really
	// anything useful that we can do when a home env resource is deleted
}
