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
    };
  } // utils.lib.eachDefaultSystem (system: with import nixpkgs
    { overlays = [ self.overlays.default ]; inherit system; }; {
    packages.default = terraform-provider-nix;

    devShells.default = mkShell {
      packages = [ go gopls terraform terraform-ls watchexec ];
    };
  });
}
