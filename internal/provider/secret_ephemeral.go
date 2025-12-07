// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure implementation satisfies interface.
var _ ephemeral.EphemeralResource = &SecretEphemeralResource{}

// SecretEphemeralResource reads a single secret from gopass.
type SecretEphemeralResource struct {
	client *GopassClient
}

// SecretModel describes the data model.
type SecretModel struct {
	Path  types.String `tfsdk:"path"`
	Value types.String `tfsdk:"value"`
}

// NewSecretEphemeralResource creates a new instance.
func NewSecretEphemeralResource() ephemeral.EphemeralResource {
	return &SecretEphemeralResource{}
}

func (r *SecretEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *SecretEphemeralResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a single secret value from the gopass store.",
		MarkdownDescription: `
Reads a single secret value from the gopass store using the native gopass library.

The secret is retrieved during each Terraform operation and is **never stored**
in state or plan files.

## Example Usage

` + "```hcl" + `
ephemeral "gopass_secret" "api_key" {
  path = "services/api/token"
}

# Use the secret value
provider "example" {
  api_key = ephemeral.gopass_secret.api_key.value
}
` + "```" + `

## GPG/Hardware Token

If your gopass store is encrypted with a hardware token (YubiKey, Nitrokey, etc.),
you will be prompted for PIN entry and/or touch confirmation during each
Terraform operation that accesses the secret.
`,
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				Description:         "Path to the secret in the gopass store (e.g., 'infrastructure/db/password').",
				MarkdownDescription: "Path to the secret in the gopass store (e.g., `infrastructure/db/password`).",
				Required:            true,
			},
			"value": schema.StringAttribute{
				Description:         "The secret value (password/first line of the secret).",
				MarkdownDescription: "The secret value (password/first line of the secret).",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (r *SecretEphemeralResource) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*GopassClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data",
			fmt.Sprintf("Expected *GopassClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *SecretEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data SecretModel

	// Read configuration
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := data.Path.ValueString()

	tflog.Debug(ctx, "Reading secret from gopass", map[string]interface{}{
		"path": path,
	})

	// Use native gopass library
	value, err := r.client.GetSecret(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read secret",
			fmt.Sprintf("Could not read secret at path %q: %s", path, err.Error()),
		)
		return
	}

	data.Value = types.StringValue(value)

	// Set result - this is NEVER written to state
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)

	tflog.Debug(ctx, "Successfully read secret from gopass", map[string]interface{}{
		"path": path,
	})
}
