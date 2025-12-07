# Example: Using gopass_env for Scaleway credentials
# ==================================================
#
# This example shows how to use the gopass provider to read
# credentials from your gopass store without storing them in state.
#
# Prerequisites:
#   - gopass configured with your GPG key
#   - Secrets stored at: env/terraform/scaleway/istr/
#     ├── SCW_ACCESS_KEY
#     ├── SCW_SECRET_KEY
#     └── SCW_DEFAULT_PROJECT_ID

terraform {
  required_version = ">= 1.11.0" # OpenTofu 1.11+ for ephemeral support

  required_providers {
    gopass = {
      source  = "registry.opentofu.org/istr/gopass"
      version = "~> 0.1"
    }
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.0"
    }
  }
}

# Configure gopass provider (optional - defaults work for most setups)
provider "gopass" {
  # Uncomment to use a specific gopass binary
  # gopass_binary = "/usr/local/bin/gopass"

  # Uncomment to use a specific store
  # store = "work"
}

# -----------------------------------------------------------------------------
# Option 1: Read entire credential set as map (gopassenv style)
# -----------------------------------------------------------------------------

ephemeral "gopass_env" "scaleway" {
  path = "env/terraform/scaleway/istr"
}

provider "scaleway" {
  access_key = ephemeral.gopass_env.scaleway.values["SCW_ACCESS_KEY"]
  secret_key = ephemeral.gopass_env.scaleway.values["SCW_SECRET_KEY"]
  project_id = ephemeral.gopass_env.scaleway.values["SCW_DEFAULT_PROJECT_ID"]
  region     = "fr-par"
}

# -----------------------------------------------------------------------------
# Option 2: Read individual secrets
# -----------------------------------------------------------------------------

# ephemeral "gopass_secret" "scw_access_key" {
#   path = "env/terraform/scaleway/istr/SCW_ACCESS_KEY"
# }
#
# ephemeral "gopass_secret" "scw_secret_key" {
#   path = "env/terraform/scaleway/istr/SCW_SECRET_KEY"
# }
#
# provider "scaleway" {
#   access_key = ephemeral.gopass_secret.scw_access_key.value
#   secret_key = ephemeral.gopass_secret.scw_secret_key.value
# }

# -----------------------------------------------------------------------------
# Example resource (credentials never stored in state)
# -----------------------------------------------------------------------------

resource "scaleway_object_bucket" "example" {
  name = "my-ephemeral-test-bucket"

  tags = {
    managed_by = "opentofu"
    note       = "credentials-not-in-state"
  }
}

output "bucket_endpoint" {
  value = scaleway_object_bucket.example.endpoint
}
