package nix

import (
	"context"

	"mtoohey.com/terraform-provider-nix/version"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// New returns a new nix provider.
func New() provider.Provider {
	return &nixProvider{}
}

// nixProvider is the provider implementation.
type nixProvider struct{}

// Metadata returns the provider type name.
func (nixProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nix"
	resp.Version = version.Version
}

// Schema defines the provider-level schema for configuration data.
func (nixProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with various Nix ecosystem constructs.",
	}
}

// Configure prepares connections for data sources and resources.
func (nixProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// DataSources defines the data sources implemented in the provider.
func (nixProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{func() datasource.DataSource { return drvDataSource{} }}
}

// Resources defines the resources implemented in the provider.
func (nixProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{func() resource.Resource { return osResource{} }}
}
