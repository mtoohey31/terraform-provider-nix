package nix

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// drvDataSource is the data source implementation.
type drvDataSource struct{}

// Metadata returns the data source type name.
func (drvDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_drv"
}

// Schema defines the schema for the data source.
func (drvDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Evaluate a derivation.",
		Attributes: map[string]schema.Attribute{
			"flake_ref": schema.StringAttribute{
				Required:    true,
				Description: "The flake reference to build.",
			},
			"out_path": schema.StringAttribute{
				Computed:    true,
				Description: "The store path produced by the derivation.",
			},
		},
	}
}

// derivationDataSourceModel maps the data source schema data.
type derivationDataSourceModel struct {
	FlakeRef types.String `tfsdk:"flake_ref"`
	OutPath  types.String `tfsdk:"out_path"`
}

// Read refreshes the Terraform state with the latest data.
func (drvDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	// Retrieve values from config
	var config derivationDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	flakeRef := config.FlakeRef.ValueString()

	// TODO: run nix in internal-json logging mode, then parse output and pass
	// through important info to the terraform logs using the tflog package.
	//   - https://github.com/maralorn/nix-output-monitor/blob/532fb9a98d2150183a97f3cfd315a6e5186d7a47/lib/NOM/Parser/JSON.hs
	//   - https://developer.hashicorp.com/terraform/tutorials/providers-plugin-framework/providers-plugin-framework-logging

	// Build flake reference and symlink result in gc root directory
	args := []string{"--extra-experimental-features", "nix-command", "build", "--no-link", "--print-out-paths", flakeRef}
	outputBytes, combinedOutput, err := combinedAndOutput(exec.Command("nix", args...))
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Build Derivation",
			fmt.Sprintf("%s; `nix build` output:\n%s", err, combinedOutput),
		)
		return
	}

	outPaths := strings.Split(string(outputBytes), "\n")
	filteredOutPaths := make([]string, 0, len(outPaths))
	for _, path := range outPaths {
		if path != "" {
			filteredOutPaths = append(filteredOutPaths, path)
		}
	}
	switch len(filteredOutPaths) {
	case 0:
		resp.Diagnostics.AddError(
			"Derivation Produced No Outputs",
			fmt.Sprintf("Derivation produced no outputs; `nix build` output:\n%s", combinedOutput),
		)
		return

	case 1:
		// happy path, continue to below

	default:
		resp.Diagnostics.AddError(
			"Derivation Produced More Than One Output",
			fmt.Sprintf("Derivation produced more than one output; `nix build` output:\n%s", combinedOutput),
		)
		return
	}

	// Set state
	diags := resp.State.Set(ctx, &derivationDataSourceModel{
		FlakeRef: config.FlakeRef,
		OutPath:  types.StringValue(filteredOutPaths[0]),
	})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
