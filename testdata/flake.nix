{
  description = "terraform-provider-nix-integration-tests";

  inputs = {
    nixpkgs.follows = "terraform-provider-nix/nixpkgs";
    utils.follows = "terraform-provider-nix/utils";

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    terraform-provider-nix.url = "path:../";
  };

  outputs =
    { home-manager
    , nixpkgs
    , self
    , terraform-provider-nix
    , utils
    }:
    utils.lib.eachDefaultSystem (system:
    let
      sshPort = 9152;
    in
    {
      packages.default = nixpkgs.lib.nixos.runTest {
        # NOTE: we can't write a test for the nix_os resource using this
        # method because you can't switch the system profile inside one of
        # these test machines.
        name = "terraform-provider-nix-hm-env";

        hostPkgs = import nixpkgs {
          overlays = [ terraform-provider-nix.overlays.default ];
          inherit system;
        };

        imports = [
          ({ pkgs, ... }: {
            defaults = { config, pkgs, ... }: {
              nixpkgs.overlays = [ terraform-provider-nix.overlays.default ];

              environment.etc = {
                "ssh/ssh_host_ed25519_key.pub".source = ./id_ed25519.pub;
                "ssh/ssh_host_ed25519_key" = {
                  source = ./id_ed25519;
                  mode = "0600";
                };
              };

              virtualisation = {
                # test machines don't have graphical output
                graphics = false;
                # required because we're going to copy a new profile into
                # the server's store
                writableStore = true;
              };
              services.openssh = {
                enable = true;
                ports = [ sshPort ];
                hostKeys = [ ];
                settings = {
                  PasswordAuthentication = false;
                  PermitRootLogin = "prohibit-password";
                };
              };
              users = {
                mutableUsers = false;
                users.root.openssh.authorizedKeys.keys = [
                  (builtins.readFile ./id_ed25519.pub)
                ];
              };
            };
            nodes = {
              server = { };

              client = { pkgs, ... }: {
                environment = {
                  etc = {
                    "server-profile1".source =
                      (home-manager.lib.homeManagerConfiguration {
                        modules = [{
                          home = {
                            file."1".text = "";
                            homeDirectory = "/root";
                            stateVersion = "23.05";
                            username = "root";
                          };
                        }];
                        inherit pkgs;
                      }).activationPackage;
                    "server-profile2".source =
                      (home-manager.lib.homeManagerConfiguration {
                        modules = [{
                          home = {
                            file."2".text = "";
                            homeDirectory = "/root";
                            stateVersion = "23.05";
                            username = "root";
                          };
                        }];
                        inherit pkgs;
                      }).activationPackage;
                    "terraform-provider-nix-filesystem-mirror".source =
                      pkgs.terraform-provider-nix-filesystem-mirror;
                  };
                  systemPackages = [ pkgs.terraform ];
                };
              };
            };
          })
        ];

        testScript = /* python */ ''
          start_all()

          client.copy_from_host("${builtins.path { path = ./main.tf; }}", "main.tf")
          client.succeed('sed -i "s,@profile-path@,$(realpath /etc/server-profile1),g" main.tf')

          client.succeed("mkdir terraform.d")
          client.succeed("ln -s /etc/terraform-provider-nix-filesystem-mirror terraform.d/plugins")

          server.wait_for_unit("sshd")
          server.wait_for_open_port(${toString sshPort})
          client.wait_for_unit("network.target")

          client.succeed("terraform init")
          client.succeed("terraform apply -auto-approve")

          server.succeed("stat ~/1")
          server.fail("stat ~/2")

          client.succeed("terraform apply -auto-approve")

          server.succeed("stat ~/1")
          server.fail("stat ~/2")

          client.succeed('sed -i "s,$(realpath /etc/server-profile1),$(realpath /etc/server-profile2),g" main.tf')
          client.succeed("terraform apply -auto-approve")

          server.fail("stat ~/1")
          server.succeed("stat ~/2")
        '';
      };
    });
}
