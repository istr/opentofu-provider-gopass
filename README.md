# terraform-provider-gopass

OpenTofu/Terraform provider for reading secrets from [gopass](https://github.com/gopasspw/gopass)
as **ephemeral values** - credentials that are never stored in state or plan files.

## Features

- 🔐 **Ephemeral-only**: Secrets exist only during plan/apply, never persisted
- 🔗 **Native gopass integration**: Links directly against gopass Go library - no subprocess spawning
- 🔑 **Hardware token support**: Works with YubiKey, Nitrokey, etc. via GPG
- 📁 **Two access patterns**:
  - `gopass_secret`: Read single secret by path
  - `gopass_env`: Read credential set as key-value map (like `gopassenv`)
- 🔄 **No state leakage**: Provider credentials don't end up in terraform.tfstate

## Requirements

- **OpenTofu 1.11+** (ephemeral resources support) or Terraform 1.10+
- **gopass** installed and configured
- GPG key available (hardware token or software key)

## Installation

### From Source

```bash
git clone https://git.ingo-struck.com/terraform-provider-gopass.git
cd terraform-provider-gopass
make install
```

### Manual Installation

```bash
# Build
go build -o terraform-provider-gopass

# Install for OpenTofu
mkdir -p ~/.local/share/opentofu/plugins/registry.opentofu.org/istr/gopass/0.1.0/linux_amd64
cp terraform-provider-gopass ~/.local/share/opentofu/plugins/registry.opentofu.org/istr/gopass/0.1.0/linux_amd64/
```

## Usage

### Provider Configuration

```hcl
terraform {
  required_version = ">= 1.11.0"

  required_providers {
    gopass = {
      source  = "registry.opentofu.org/istr/gopass"
      version = "~> 0.1"
    }
  }
}

# No configuration needed - uses gopass's native config
provider "gopass" {}
```

### Reading a Credential Set (gopassenv style)

Given this gopass structure:

```
env/terraform/scaleway/istr/
├── SCW_ACCESS_KEY
├── SCW_SECRET_KEY
└── SCW_DEFAULT_PROJECT_ID
```

Read all as a map:

```hcl
ephemeral "gopass_env" "scaleway" {
  path = "env/terraform/scaleway/istr"
}

provider "scaleway" {
  access_key = ephemeral.gopass_env.scaleway.values["SCW_ACCESS_KEY"]
  secret_key = ephemeral.gopass_env.scaleway.values["SCW_SECRET_KEY"]
  project_id = ephemeral.gopass_env.scaleway.values["SCW_DEFAULT_PROJECT_ID"]
}
```

### Reading Individual Secrets

```hcl
ephemeral "gopass_secret" "db_password" {
  path = "infrastructure/database/admin_password"
}

resource "postgresql_role" "admin" {
  name     = "admin"
  password = ephemeral.gopass_secret.db_password.value  # write-only attribute
}
```

## Ephemeral Resources

### gopass_secret

Reads a single secret from the gopass store.

#### Arguments

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Path to the secret in gopass |

#### Attributes

| Name | Type | Description |
|------|------|-------------|
| `value` | string | The secret value (first line only) |

### gopass_env

Reads all secrets under a path as a key-value map.

#### Arguments

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Path prefix in gopass store |

#### Attributes

| Name | Type | Description |
|------|------|-------------|
| `values` | map(string) | Map of secret names to values |

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  tofu plan / tofu apply                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. OpenTofu calls provider's Open() method                 │
│                                                             │
│  2. Provider uses gopass Go library directly:               │
│     ├── api.New(ctx) → initializes store once              │
│     ├── store.List(ctx) → lists secrets                    │
│     └── store.Get(ctx, path, "latest") → retrieves secret  │
│         └── GPG decryption (may require PIN/touch)         │
│                                                             │
│  3. Secret returned to OpenTofu in memory only              │
│     └── Used for provider config, write-only attributes     │
│                                                             │
│  4. Operation completes, secret discarded                   │
│     └── Nothing written to state or plan                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     OpenTofu/Terraform                      │
├─────────────────────────────────────────────────────────────┤
│                    terraform-provider-gopass                │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │ GopassClient    │  │ Ephemeral Resources              │  │
│  │                 │  │  - gopass_secret (single value)  │  │
│  │ • ensureStore() │──│  - gopass_env (key-value map)    │  │
│  │ • GetSecret()   │  │                                  │  │
│  │ • GetEnvSecrets │  │ Values exist only in memory      │  │
│  └────────┬────────┘  └──────────────────────────────────┘  │
├───────────┼─────────────────────────────────────────────────┤
│           │           gopass Library (linked)               │
│           v                                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ github.com/gopasspw/gopass/pkg/gopass/api               ││
│  │  • api.New(ctx) → Store                                 ││
│  │  • store.List(ctx) → []string                           ││
│  │  • store.Get(ctx, name, revision) → Secret              ││
│  │  • secret.Password() → string                           ││
│  └────────┬────────────────────────────────────────────────┘│
├───────────┼─────────────────────────────────────────────────┤
│           v                                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    GPG Agent                            ││
│  │         (handles hardware token interaction)            ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Security Considerations

### What's Protected

- ✅ Secrets never written to `terraform.tfstate`
- ✅ Secrets never written to plan files
- ✅ No subprocess spawning (no secrets in process arguments)
- ✅ Hardware token provides physical authentication factor
- ✅ Each operation requires fresh authentication

### What's NOT Protected

- ⚠️ Secrets exist in memory during execution
- ⚠️ Debug logs might expose paths (not values)
- ⚠️ Process memory could theoretically be dumped
- ⚠️ Resources created with secrets may store them externally

### Recommendations

1. **Use hardware tokens**: YubiKey/Nitrokey with touch requirement
2. **Enable state encryption**: Use OpenTofu's state encryption as defense-in-depth
3. **Audit gopass access**: Monitor GPG agent activity
4. **Prefer write-only attributes**: When passing secrets to resources

## Development

```bash
# Setup
git clone https://git.ingo-struck.com/terraform-provider-gopass.git
cd terraform-provider-gopass
go mod download

# Build & Install
make build
make install

# Test
make test

# Format & Lint
make fmt
make lint
```

## Comparison with Alternatives

| Approach | Secrets in State | Subprocess | Hardware Token |
|----------|-----------------|------------|----------------|
| **gopass ephemeral (native)** | ❌ No | ❌ No | ✅ Yes |
| gopass ephemeral (exec) | ❌ No | ✅ Yes | ✅ Yes |
| Environment variables | ❌ No | N/A | ✅ Yes |
| Vault data source | ✅ Yes | ❌ No | Via Vault |
| External data source | ✅ Yes | ✅ Yes | ✅ Yes |
| SOPS provider | ✅ Yes | ✅ Yes | Via GPG |
| State encryption | ✅ Yes (encrypted) | N/A | Via KMS |

## API Stability Note

The gopass library includes this warning:

> Feel free to report feedback on API design and missing features but please note that
> bug reports will be silently ignored and the API WILL CHANGE WITHOUT NOTICE until this note is gone.

This provider may need updates when gopass releases new versions. Pin your gopass
dependency version in `go.mod` for stability.

## License

MPL-2.0

## Contributing

Contributions welcome! Please open an issue first to discuss proposed changes.
