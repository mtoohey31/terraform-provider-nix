# terraform-provider-nix

A [Terraform provider](https://developer.hashicorp.com/terraform/cdktf/concepts/providers) for [Nix](https://nixos.org) with first-class flake support.

## Installation

> This provider is not published in any provider registory, so just adding `terraform.mtoohey.com/nix/nix` to your `required_providers` block and running `terraform init` won't work. Follow one of the sections below so `terraform init` will be able to find the provider.

---

### With `terraform.d` in the Current Directory

This method is temporary at best, but is a good option if you'd just like to try out the provider. Run the following command:

```shell
nix build github:mtoohey31/terraform-provider-nix#terraform-provider-nix-filesystem-mirror --out-link terraform.d/plugins
```

This will create a symlink at `terraform.d/plugins` in the current directory that points to a filesystem mirror in the Nix store containing the provider binary for the current platform. This will allow `terraform init` to find the provider because `$PWD/terraform.d/plugins` is an [implied local mirror directory](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories).

### In a Nix devShell

This method relies on overriding the Terraform config file using the `TF_CLI_CONFIG_FILE` environment variable. If you have an existing Terraform config file that still needs to be respected, this option won't work for you.

Here is a minimal example flake containing a devShell that uses this method:

```nix
{
  inputs = {
    terraform-provider-nix.url = "github:mtoohey31/terraform-provider-nix";
    nixpkgs.follows = "terraform-provider-nix/nixpkgs";
    utils.follows = "terraform-provider-nix/utils";
  };

  outputs = { nixpkgs, terraform-provider-nix, utils, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        inherit (import nixpkgs {
          overlays = [ terraform-provider-nix.overlays.default ];
          inherit system;
        }) mkShell terraform terraform-provider-nix-config-file;
      in
      {
        devShells.default = mkShell {
          packages = [ terraform ];
          shellHook = ''
            export TF_CLI_CONFIG_FILE=${terraform-provider-nix-config-file}
          '';
        };
      });
}
```

The config file produced by the `terraform-provider-nix-config-file` derivation will instruct Terraform to use a [filesystem mirror](https://developer.hashicorp.com/terraform/cli/config/config-file#filesystem_mirror) in the Nix store for the `terraform.mtoohey.com/nix/nix` provider. It will specify that the [direct](https://developer.hashicorp.com/terraform/cli/config/config-file#direct) installation method should be used for all other providers.

### Manually

Build the binary, either with Nix using:

```shell
nix build github:mtoohey31/terraform-provider-nix # creates ./result/
```

...or manually by cloning the repository, installing Go, and running:

```shell
go build # creates ./terraform-provider-nix(.exe)?
```

Then select a method from the [Terraform provider installation docs](https://developer.hashicorp.com/terraform/cli/config/config-file#provider-installation) for installing the binary you've created.

## Usage

See [docs](./docs). Note that `nix` must be installed on all machines where `terraform` is run, since reading state and applying changes requires running `nix` commands under the hood.
