terraform {
  required_providers {
    nix = {
      source  = "terraform.mtoohey.com/nix/nix"
      version = "0.3.0"
    }
  }
}

resource "nix_hm_env" "hello" {
  profile_path = "@profile-path@"
  ssh_conn = {
    user             = "root"
    host             = "server"
    port             = 9152
    public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUPNknWJNq8Ymy8wPr0fQyvon/ubsLUTwoonXjzzCqD"
    private_key_path = pathexpand("/etc/ssh/ssh_host_ed25519_key")
  }
}
