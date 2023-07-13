{
  description = "terraform-provider-nix";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }: {
    overlays.default = final: _: {
      terraform-provider-nix = final.buildGoModule {
        pname = "terraform-provider-nix";
        version = builtins.readFile version/version.txt;
        src = builtins.path { path = ./.; name = "terraform-provider-nix-src"; };
        vendorSha256 = null;
        nativeBuildInputs = [ final.terraform ];
        postBuild = ''
          go generate
        '';
        postInstall = ''
          mkdir -p $out/share/doc
          cp -r docs $out/share/doc/terraform-provider-nix
        '';
        preCheck = ''
          go generate ./internal/nix
        '';
      };

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
  } // utils.lib.eachDefaultSystem (system: with import nixpkgs
    { overlays = [ self.overlays.default ]; inherit system; }; {
    packages = {
      default = terraform-provider-nix;
      inherit terraform-provider-nix terraform-provider-nix-config-file
        terraform-provider-nix-filesystem-mirror;
    };

    devShells.default = mkShell {
      packages = [ go gopls terraform terraform-ls ];
    };
  });
}
