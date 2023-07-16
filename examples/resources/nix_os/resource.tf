terraform {
  required_providers {
    nix = {
      source  = "terraform.mtoohey.com/nix/nix"
      version = "0.1.1"
    }
  }
}

data "nix_drv" "hello_system_profile" {
  flake_ref = ".#nixosConfigurations.hello.config.system.build.toplevel"
}

resource "nix_os" "hello" {
  profile_path     = data.nix_drv.hello_system_profile.out_path
  user             = "hello" # user must have permission to change the system profile
  host             = "hello.example.com"
  port             = 2222
  public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
  private_key_path = pathexpand("~/.ssh/id_ed25519")
}
