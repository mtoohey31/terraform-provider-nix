{
  description = "terraform-provider-nix-hm-env-example";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, home-manager, nixpkgs }: {
    homeManagerConfigurations.hello = home-manager.lib.homeManagerConfiguration {
      modules = [{
        home = {
          homeDirectory = "/home/hello";
          stateVersion = "23.05";
          username = "hello";
        };
      }];
      pkgs = import nixpkgs { system = "x86_64-linux"; };
    };
  };
}
