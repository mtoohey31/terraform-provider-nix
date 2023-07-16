terraform {
  required_providers {
    nix = {
      source  = "terraform.mtoohey.com/nix/nix"
      version = "0.2.0"
    }
  }
}

data "nix_drv" "hello" {
  flake_ref = ".#hello"
}
