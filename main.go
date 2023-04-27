package main

import (
	"context"

	"mtoohey.com/terraform-provider-nix/internal/nix"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	providerserver.Serve(context.Background(), nix.New, providerserver.ServeOpts{
		Address: "terraform.mtoohey.com/nix/nix",
	})
}
