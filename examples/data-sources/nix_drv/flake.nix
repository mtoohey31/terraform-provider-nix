{
  description = "terraform-provider-nix-drv-example";

  inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux = {
      inherit (import nixpkgs { system = "x86_64-linux"; }) hello;
    };
  };
}
