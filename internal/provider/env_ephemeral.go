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
var _ ephemeral.EphemeralResource = &EnvEphemeralResource{}

// EnvEphemeralResource reads a subtree from gopass as environment variables.
type EnvEphemeralResource struct {
	client *GopassClient
}

// EnvModel describes the data model.
type EnvModel struct {
	Path   types.String `tfsdk:"path"`
	Values types.Map    `tfsdk:"values"`
}

// NewEnvEphemeralResource creates a new instance.
func NewEnvEphemeralResource() ephemeral.EphemeralResource {
	return &EnvEphemeralResource{}
}

func (r *EnvEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_env"
}

func (r *EnvEphemeralResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads all secrets under a path as a key-value map (environment variable style).",
		MarkdownDescription: `
Reads all secrets under a path as a key-value map, using the native gopass library.

Each secret name under the path becomes a key, and the secret's first line becomes the value.
This is ideal for reading credential sets like:

` + "```" + `
env/terraform/scaleway/istr/
├── SCW_ACCESS_KEY
├── SCW_SECRET_KEY
└── SCW_DEFAULT_PROJECT_ID
` + "```" + `

## Example Usage

` + "```hcl" + `
ephemeral "gopass_env" "scaleway" {
  path = "env/terraform/scaleway/istr"
}

provider "scaleway" {
  access_key = ephemeral.gopass_env.scaleway.values["SCW_ACCESS_KEY"]
  secret_key = ephemeral.gopass_env.scaleway.values["SCW_SECRET_KEY"]
  project_id = ephemeral.gopass_env.scaleway.values["SCW_DEFAULT_PROJECT_ID"]
}
` + "```" + `

## Notes

- Only immediate children of the path are included (not recursive)
- Each secret's first line is used as the value (gopass password convention)
- Secret names become map keys as-is (typically UPPER_SNAKE_CASE for env vars)
- No subprocess spawning - direct library access for better performance
`,
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				Description:         "Path prefix in the gopass store (e.g., 'env/terraform/scaleway/istr').",
				MarkdownDescription: "Path prefix in the gopass store (e.g., `env/terraform/scaleway/istr`).",
				Required:            true,
			},
			"values": schema.MapAttribute{
				Description:         "Map of secret names to their values.",
				MarkdownDescription: "Map of secret names to their values.",
				Computed:            true,
				Sensitive:           true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *EnvEphemeralResource) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
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

func (r *EnvEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data EnvModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	basePath := data.Path.ValueString()

	tflog.Debug(ctx, "Reading env secrets from gopass", map[string]interface{}{
		"path": basePath,
	})

	// Use native gopass library
	values, err := r.client.GetEnvSecrets(ctx, basePath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read secrets",
			fmt.Sprintf("Could not read secrets under path %q: %s", basePath, err.Error()),
		)
		return
	}

	if len(values) == 0 {
		resp.Diagnostics.AddWarning(
			"No secrets found",
			fmt.Sprintf("No immediate child secrets found under path %q", basePath),
		)
	}

	// Convert to types.Map
	// types.MapValueFrom with types.StringType and map[string]string is guaranteed to succeed
	mapValue, _ := types.MapValueFrom(ctx, types.StringType, values)
	data.Values = mapValue

	// Set result - NEVER written to state
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)

	tflog.Debug(ctx, "Successfully read env secrets from gopass", map[string]interface{}{
		"path":  basePath,
		"count": len(values),
	})
}
