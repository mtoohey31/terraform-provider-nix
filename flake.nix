{
  description = "terraform-provider-nix";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }: {
    overlays.default = final: _: {
      terraform-provider-nix = final.callPackage
        ({ buildGoModule, lib, makeWrapper, runCommand, terraform }:
          buildGoModule ({
            pname = "terraform-provider-nix";
            version = builtins.readFile version/version.txt;
            src = builtins.path { path = ./.; name = "terraform-provider-nix-src"; };
            vendorHash = null;
            nativeBuildInputs = [ terraform ];
            postInstall = ''
              mkdir -p $out/share/doc
              cp -r docs $out/share/doc/terraform-provider-nix
            '';
            preCheck = ''
              go generate ./internal/nix
            '';
          } // lib.optionalAttrs (lib.getName terraform == "opentofu") {
            nativeBuildInputs = [
              terraform
              (runCommand "terraform-wrapper"
                {
                  buildInputs = [ makeWrapper ];
                } ''
                makeWrapper ${terraform}/bin/tofu $out/bin/terraform
              ''
              )
            ];

            TF_ACC_TERRAFORM_PATH = "${terraform}/bin/tofu";
            TF_ACC_PROVIDER_NAMESPACE = "nix";
            TF_ACC_PROVIDER_HOST = "terraform.mtoohey.com";
          }))
        { terraform = final.opentofu; };

      terraform-provider-nix-config-file = final.writeText
        "terraform-provider-nix-config-file"
        /* hcl */ ''
        provider_installation {
          filesystem_mirror {
            path    = "${final.terraform-provider-nix-filesystem-mirror}"
            include = ["terraform.mtoohey.com/nix/nix"]
          }

          direct {
            exclude = ["terraform.mtoohey.com/nix/nix"]
          }
        }
      '';

      terraform-provider-nix-filesystem-mirror =
        let
          inherit (final) go terraform-provider-nix;
          inherit (terraform-provider-nix) version;
          inherit (go) GOOS GOARCH;
        in
        final.runCommand
          "terraform-provider-nix-filesystem-mirror"
          { } ''
          dest_dir=$out/terraform.mtoohey.com/nix/nix/${version}/${GOOS}_${GOARCH}
          mkdir -p $dest_dir
          ln -s ${terraform-provider-nix}/bin/terraform-provider-nix \
            $dest_dir/terraform-provider-nix_v${version}
        '';
    };
  } // utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        overlays = [ self.overlays.default ];
        inherit system;
      };
      inherit (pkgs) gopls mkShell opentofu terraform terraform-ls
        terraform-provider-nix terraform-provider-nix-config-file
        terraform-provider-nix-filesystem-mirror;
    in
    {
      packages = {
        default = terraform-provider-nix;
        inherit terraform-provider-nix terraform-provider-nix-config-file
          terraform-provider-nix-filesystem-mirror;
        terraform-provider-nix-with-terraform =
          terraform-provider-nix.override { inherit terraform; };
      };

      devShells.default = mkShell {
        inputsFrom = [ terraform-provider-nix ];
        packages = [ gopls opentofu terraform terraform-ls ];
      };
    });
}
