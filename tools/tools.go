//go:build tools

package tools

// Ensure documentation generator is not removed from go.mod
import _ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
