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
    {
      overlays = [
        (final: _: {
          gow = final.buildGoModule rec {
            pname = "gow";
            version = builtins.substring 0 7 src.rev;
            src = final.fetchFromGitHub {
              owner = "mitranim";
              repo = pname;
              rev = "a5bfab26a0e42ee646f0969ac3397e80e5e3b1df";
              sha256 = "vlIbVoAxeeQ1SB8FmSAfQ35fX6f+/VGZmrPDdA3HTvs=";
            };
            vendorSha256 = "o6KltbjmAN2w9LMeS9oozB0qz9tSMYmdDW3CwUNChzA=";
          };
        })
        self.overlays.default
      ]; inherit system;
    }; {
    packages.default = terraform-provider-nix;

    devShells.default = mkShell {
      packages = [ go gopls gow terraform terraform-ls ];
    };
  });
}
