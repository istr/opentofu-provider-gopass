// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure implementation satisfies interfaces.
var (
	_ resource.Resource                = &SecretResource{}
	_ resource.ResourceWithConfigure   = &SecretResource{}
	_ resource.ResourceWithImportState = &SecretResource{}
)

// SecretResource writes secrets to gopass with write-only value support.
type SecretResource struct {
	client *GopassClient
}

// SecretResourceModel describes the resource data model.
type SecretResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Path           types.String `tfsdk:"path"`
	ValueWO        types.String `tfsdk:"value_wo"`
	ValueWOVersion types.Int64  `tfsdk:"value_wo_version"`
	DeleteOnRemove types.Bool   `tfsdk:"delete_on_remove"`
	RevisionCount  types.Int64  `tfsdk:"revision_count"`
}

// NewSecretResource creates a new instance.
func NewSecretResource() resource.Resource {
	return &SecretResource{}
}

func (r *SecretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *SecretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Writes a secret to the gopass store using write-only attributes. " +
			"The secret value is never stored in Terraform state.",
		MarkdownDescription: `
Writes a secret to the gopass store using **write-only attributes**.

The secret value (` + "`value_wo`" + `) is sent to gopass but **never stored in Terraform state**.
This is ideal for storing generated credentials like API keys.

## Example Usage

` + "```hcl" + `
# Store a generated API key in gopass
resource "gopass_secret" "api_key" {
  path             = "env/terraform/scaleway/infra-manager/SCW_SECRET_KEY"
  value_wo         = scaleway_iam_api_key.infra_manager.secret_key
  value_wo_version = 1
}

# Use with ephemeral random password
ephemeral "random_password" "db" {
  length = 32
}

resource "gopass_secret" "db_password" {
  path             = "infrastructure/database/admin_password"
  value_wo         = ephemeral.random_password.db.result
  value_wo_version = 1
}
` + "```" + `

## Write-Only Behavior

- ` + "`value_wo`" + ` accepts ephemeral values (from ephemeral resources)
- The value is written to gopass on create and when ` + "`value_wo_version`" + ` changes
- The value is **never** stored in Terraform state or plan files
- Increment ` + "`value_wo_version`" + ` to trigger a secret update

## Import

Existing secrets can be imported:

` + "```bash" + `
tofu import gopass_secret.api_key "env/terraform/scaleway/infra-manager/SCW_SECRET_KEY"
` + "```" + `

After import, set ` + "`value_wo`" + ` and ` + "`value_wo_version`" + ` in your configuration.
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The path of the secret (same as path attribute).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"path": schema.StringAttribute{
				Description:         "Path in the gopass store where the secret will be written.",
				MarkdownDescription: "Path in the gopass store where the secret will be written (e.g., `env/terraform/scaleway/api_key`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"value_wo": schema.StringAttribute{
				Description: "The secret value to write. This is a write-only attribute - " +
					"it will never be stored in state or plan files. Accepts ephemeral values.",
				MarkdownDescription: "The secret value to write. This is a **write-only** attribute - " +
					"it will never be stored in state or plan files. Accepts ephemeral values.",
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"value_wo_version": schema.Int64Attribute{
				Description: "Version number for the write-only value. Increment this to trigger " +
					"a secret update when value_wo changes.",
				MarkdownDescription: "Version number for the write-only value. **Increment this** to trigger " +
					"a secret update when `value_wo` changes.",
				Optional: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"delete_on_remove": schema.BoolAttribute{
				Description:         "Whether to delete the secret from gopass when the resource is destroyed. Defaults to true.",
				MarkdownDescription: "Whether to delete the secret from gopass when the resource is destroyed. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"revision_count": schema.Int64Attribute{
				Description: "Number of revisions in gopass for this secret. Used for drift detection. " +
					"A warning is shown if this changes outside of Terraform. " +
					"Note: Not all gopass backends support versioning - in that case this will be 1 if the secret exists.",
				MarkdownDescription: "Number of revisions in gopass for this secret. Used for **drift detection**. " +
					"A warning is shown if this changes outside of Terraform. " +
					"Note: Not all gopass backends support versioning - in that case this will be `1` if the secret exists.",
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *SecretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*GopassClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *GopassClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

//nolint:gocritic // hugeParam: Terraform framework interface requirement
func (r *SecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := data.Path.ValueString()

	tflog.Debug(ctx, "Creating gopass secret", map[string]interface{}{
		"path": secretPath,
	})

	// Get write-only value from config (not plan, as write-only values are only in config)
	var config SecretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the secret if value_wo is provided
	if !config.ValueWO.IsNull() && !config.ValueWO.IsUnknown() {
		value := config.ValueWO.ValueString()
		if err := r.client.SetSecret(ctx, secretPath, value); err != nil {
			resp.Diagnostics.AddError(
				"Failed to create secret",
				fmt.Sprintf("Could not write secret to gopass at %q: %s", secretPath, err.Error()),
			)
			return
		}
	} else {
		resp.Diagnostics.AddWarning(
			"No value provided",
			"The secret was created but no value_wo was provided. The secret in gopass may be empty or unchanged.",
		)
	}

	// Get revision count for drift detection
	revCount, err := r.client.GetRevisionCount(ctx, secretPath)
	if err != nil {
		tflog.Warn(ctx, "Could not get revision count", map[string]interface{}{
			"path":  secretPath,
			"error": err.Error(),
		})
		revCount = 1 // Fallback: we know it exists
	}
	data.RevisionCount = types.Int64Value(revCount)

	// Set ID to path
	data.ID = data.Path

	tflog.Debug(ctx, "Created gopass secret", map[string]interface{}{
		"path": secretPath,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

//nolint:gocritic // hugeParam: Terraform framework interface requirement
func (r *SecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SecretResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := data.Path.ValueString()

	tflog.Debug(ctx, "Reading gopass secret", map[string]interface{}{
		"path": secretPath,
	})

	// Only check if secret exists - we never read the value back
	exists, err := r.client.SecretExists(ctx, secretPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read secret",
			fmt.Sprintf("Could not check if secret exists at %q: %s", secretPath, err.Error()),
		)
		return
	}

	if !exists {
		// Secret was deleted outside of Terraform
		resp.State.RemoveResource(ctx)
		return
	}

	// Check for drift via revision count
	currentRevCount, err := r.client.GetRevisionCount(ctx, secretPath)
	if err != nil {
		tflog.Warn(ctx, "Could not get revision count for drift detection", map[string]interface{}{
			"path":  secretPath,
			"error": err.Error(),
		})
	} else {
		storedRevCount := data.RevisionCount.ValueInt64()

		// Only warn if we have a meaningful comparison
		// (storedRevCount > 0 means we had a previous count, currentRevCount > 1 means versioning is supported)
		if storedRevCount > 0 && currentRevCount > storedRevCount {
			resp.Diagnostics.AddWarning(
				"Secret modified outside of Terraform",
				fmt.Sprintf(
					"The secret at %q has %d revisions, but Terraform expected %d. "+
						"This indicates the secret was modified outside of Terraform. "+
						"The actual value may differ from what Terraform last wrote. "+
						"Consider incrementing value_wo_version to overwrite with the intended value.",
					secretPath, currentRevCount, storedRevCount,
				),
			)
		}

		// Update stored revision count
		data.RevisionCount = types.Int64Value(currentRevCount)
	}

	// Keep existing state (with updated revision count)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

//nolint:gocritic // hugeParam: Terraform framework interface requirement
func (r *SecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SecretResourceModel
	var state SecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := data.Path.ValueString()

	tflog.Debug(ctx, "Updating gopass secret", map[string]interface{}{
		"path": secretPath,
	})

	// Get write-only value from config
	var config SecretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if value_wo_version changed - this triggers the update
	versionChanged := false
	if !data.ValueWOVersion.IsNull() && !state.ValueWOVersion.IsNull() {
		versionChanged = data.ValueWOVersion.ValueInt64() != state.ValueWOVersion.ValueInt64()
	} else if !data.ValueWOVersion.IsNull() && state.ValueWOVersion.IsNull() {
		versionChanged = true
	}

	// Write the secret if version changed and value_wo is provided
	if versionChanged {
		if !config.ValueWO.IsNull() && !config.ValueWO.IsUnknown() {
			value := config.ValueWO.ValueString()
			if err := r.client.SetSecret(ctx, secretPath, value); err != nil {
				resp.Diagnostics.AddError(
					"Failed to update secret",
					fmt.Sprintf("Could not write secret to gopass at %q: %s", secretPath, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Updated gopass secret (value_wo_version changed)", map[string]interface{}{
				"path":        secretPath,
				"old_version": state.ValueWOVersion.ValueInt64(),
				"new_version": data.ValueWOVersion.ValueInt64(),
			})
		} else {
			resp.Diagnostics.AddWarning(
				"Version changed but no value provided",
				"value_wo_version was incremented but no value_wo was provided. The secret in gopass was not updated.",
			)
		}
	}

	// Update revision count after write
	revCount, err := r.client.GetRevisionCount(ctx, secretPath)
	if err != nil {
		tflog.Warn(ctx, "Could not get revision count after update", map[string]interface{}{
			"path":  secretPath,
			"error": err.Error(),
		})
		// Keep previous count if we can't get new one
		revCount = state.RevisionCount.ValueInt64()
	}
	data.RevisionCount = types.Int64Value(revCount)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

//nolint:gocritic // hugeParam: Terraform framework interface requirement
func (r *SecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SecretResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := data.Path.ValueString()
	deleteOnRemove := data.DeleteOnRemove.ValueBool()

	tflog.Debug(ctx, "Deleting gopass secret resource", map[string]interface{}{
		"path":             secretPath,
		"delete_on_remove": deleteOnRemove,
	})

	if deleteOnRemove {
		// Check if secret exists before deleting
		exists, err := r.client.SecretExists(ctx, secretPath)
		if err != nil {
			resp.Diagnostics.AddWarning(
				"Failed to check secret existence",
				fmt.Sprintf("Could not verify if secret exists at %q: %s", secretPath, err.Error()),
			)
			return
		}

		if exists {
			if err := r.client.RemoveSecret(ctx, secretPath); err != nil {
				resp.Diagnostics.AddError(
					"Failed to remove secret",
					fmt.Sprintf("Could not remove secret from gopass at %q: %s", secretPath, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Removed gopass secret", map[string]interface{}{
				"path": secretPath,
			})
		}
	} else {
		tflog.Info(ctx, "Keeping gopass secret (delete_on_remove=false)", map[string]interface{}{
			"path": secretPath,
		})
	}
}

func (r *SecretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	secretPath := req.ID

	tflog.Debug(ctx, "Importing gopass secret", map[string]interface{}{
		"path": secretPath,
	})

	// Verify the secret exists
	exists, err := r.client.SecretExists(ctx, secretPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to import secret",
			fmt.Sprintf("Could not check if secret exists at %q: %s", secretPath, err.Error()),
		)
		return
	}

	if !exists {
		resp.Diagnostics.AddError(
			"Secret not found",
			fmt.Sprintf("No secret exists at path %q in gopass", secretPath),
		)
		return
	}

	// Get revision count
	revCount, err := r.client.GetRevisionCount(ctx, secretPath)
	if err != nil {
		tflog.Warn(ctx, "Could not get revision count during import", map[string]interface{}{
			"path":  secretPath,
			"error": err.Error(),
		})
		revCount = 1 // Fallback
	}

	// Import with path as ID
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), secretPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), secretPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("delete_on_remove"), true)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("revision_count"), revCount)...)
}
