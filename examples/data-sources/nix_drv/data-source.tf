terraform {
  required_providers {
    nix = {
      source  = "terraform.mtoohey.com/nix/nix"
      version = "0.1.1"
    }
  }
}

data "nix_drv" "hello" {
  flake_ref = ".#hello"
}
