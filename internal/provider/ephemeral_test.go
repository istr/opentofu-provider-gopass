// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/gopasspw/gopass/pkg/gopass/secrets"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ============ SecretEphemeralResource Tests ============

func TestSecretEphemeralResource_NewSecretEphemeralResource(t *testing.T) {
	r := NewSecretEphemeralResource()
	if r == nil {
		t.Fatal("NewSecretEphemeralResource returned nil")
	}
}

func TestSecretEphemeralResource_Metadata(t *testing.T) {
	r := &SecretEphemeralResource{}
	req := ephemeral.MetadataRequest{
		ProviderTypeName: "gopass",
	}
	resp := &ephemeral.MetadataResponse{}

	r.Metadata(context.Background(), req, resp)

	if resp.TypeName != "gopass_secret" {
		t.Errorf("expected TypeName 'gopass_secret', got %q", resp.TypeName)
	}
}

func TestSecretEphemeralResource_Schema(t *testing.T) {
	r := &SecretEphemeralResource{}
	req := ephemeral.SchemaRequest{}
	resp := &ephemeral.SchemaResponse{}

	r.Schema(context.Background(), req, resp)

	// Verify required attributes exist
	if _, ok := resp.Schema.Attributes["path"]; !ok {
		t.Error("expected 'path' attribute in schema")
	}
	if _, ok := resp.Schema.Attributes["value"]; !ok {
		t.Error("expected 'value' attribute in schema")
	}

	// Verify path is required
	pathAttr := resp.Schema.Attributes["path"]
	if !pathAttr.IsRequired() {
		t.Error("expected 'path' to be required")
	}

	// Verify value is computed and sensitive
	valueAttr := resp.Schema.Attributes["value"]
	if !valueAttr.IsComputed() {
		t.Error("expected 'value' to be computed")
	}
	if !valueAttr.IsSensitive() {
		t.Error("expected 'value' to be sensitive")
	}
}

func TestSecretEphemeralResource_Configure(t *testing.T) {
	r := &SecretEphemeralResource{}
	client := NewGopassClient("")

	req := ephemeral.ConfigureRequest{
		ProviderData: client,
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	if r.client != client {
		t.Error("expected client to be set")
	}
}

func TestSecretEphemeralResource_Configure_NilData(t *testing.T) {
	r := &SecretEphemeralResource{}

	req := ephemeral.ConfigureRequest{
		ProviderData: nil,
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestSecretEphemeralResource_Configure_InvalidType(t *testing.T) {
	r := &SecretEphemeralResource{}

	req := ephemeral.ConfigureRequest{
		ProviderData: "invalid",
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error for invalid provider data type")
	}
}

func TestSecretEphemeralResource_Open(t *testing.T) {
	r := &SecretEphemeralResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	// Add a test secret
	secret := secrets.New()
	secret.SetPassword("test-password")
	mockStore.secrets["test/secret"] = secret

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":  tftypes.String,
			"value": tftypes.String,
		},
	}, map[string]tftypes.Value{
		"path":  tftypes.NewValue(tftypes.String, "test/secret"),
		"value": tftypes.NewValue(tftypes.String, nil),
	})

	// Initialize Result properly with the schema
	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":  tftypes.String,
			"value": tftypes.String,
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestSecretEphemeralResource_Open_NotFound(t *testing.T) {
	r := &SecretEphemeralResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":  tftypes.String,
			"value": tftypes.String,
		},
	}, map[string]tftypes.Value{
		"path":  tftypes.NewValue(tftypes.String, "nonexistent"),
		"value": tftypes.NewValue(tftypes.String, nil),
	})

	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":  tftypes.String,
			"value": tftypes.String,
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error for non-existent secret")
	}
}

// ============ EnvEphemeralResource Tests ============

func TestEnvEphemeralResource_NewEnvEphemeralResource(t *testing.T) {
	r := NewEnvEphemeralResource()
	if r == nil {
		t.Fatal("NewEnvEphemeralResource returned nil")
	}
}

func TestEnvEphemeralResource_Metadata(t *testing.T) {
	r := &EnvEphemeralResource{}
	req := ephemeral.MetadataRequest{
		ProviderTypeName: "gopass",
	}
	resp := &ephemeral.MetadataResponse{}

	r.Metadata(context.Background(), req, resp)

	if resp.TypeName != "gopass_env" {
		t.Errorf("expected TypeName 'gopass_env', got %q", resp.TypeName)
	}
}

func TestEnvEphemeralResource_Schema(t *testing.T) {
	r := &EnvEphemeralResource{}
	req := ephemeral.SchemaRequest{}
	resp := &ephemeral.SchemaResponse{}

	r.Schema(context.Background(), req, resp)

	// Verify required attributes exist
	if _, ok := resp.Schema.Attributes["path"]; !ok {
		t.Error("expected 'path' attribute in schema")
	}
	if _, ok := resp.Schema.Attributes["values"]; !ok {
		t.Error("expected 'values' attribute in schema")
	}

	// Verify path is required
	pathAttr := resp.Schema.Attributes["path"]
	if !pathAttr.IsRequired() {
		t.Error("expected 'path' to be required")
	}

	// Verify values is computed and sensitive
	valuesAttr := resp.Schema.Attributes["values"]
	if !valuesAttr.IsComputed() {
		t.Error("expected 'values' to be computed")
	}
	if !valuesAttr.IsSensitive() {
		t.Error("expected 'values' to be sensitive")
	}
}

func TestEnvEphemeralResource_Configure(t *testing.T) {
	r := &EnvEphemeralResource{}
	client := NewGopassClient("")

	req := ephemeral.ConfigureRequest{
		ProviderData: client,
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	if r.client != client {
		t.Error("expected client to be set")
	}
}

func TestEnvEphemeralResource_Configure_NilData(t *testing.T) {
	r := &EnvEphemeralResource{}

	req := ephemeral.ConfigureRequest{
		ProviderData: nil,
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestEnvEphemeralResource_Configure_InvalidType(t *testing.T) {
	r := &EnvEphemeralResource{}

	req := ephemeral.ConfigureRequest{
		ProviderData: "invalid",
	}
	resp := &ephemeral.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error for invalid provider data type")
	}
}

func TestEnvEphemeralResource_Open(t *testing.T) {
	r := &EnvEphemeralResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	// Add test secrets
	secret1 := secrets.New()
	secret1.SetPassword("value1")
	mockStore.secrets["env/test/KEY1"] = secret1

	secret2 := secrets.New()
	secret2.SetPassword("value2")
	mockStore.secrets["env/test/KEY2"] = secret2

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, map[string]tftypes.Value{
		"path":   tftypes.NewValue(tftypes.String, "env/test"),
		"values": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})

	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestEnvEphemeralResource_Open_Empty(t *testing.T) {
	r := &EnvEphemeralResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, map[string]tftypes.Value{
		"path":   tftypes.NewValue(tftypes.String, "empty/path"),
		"values": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})

	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	// Should have a warning about no secrets found, no error
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestEnvEphemeralResource_Open_GetEnvSecretsError(t *testing.T) {
	r := &EnvEphemeralResource{}
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "list error"
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, map[string]tftypes.Value{
		"path":   tftypes.NewValue(tftypes.String, "env/test"),
		"values": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})

	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	// Should have an error since GetEnvSecrets failed
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for GetEnvSecrets failure")
	}
}

func TestEnvEphemeralResource_Open_ConfigGetError(t *testing.T) {
	r := &EnvEphemeralResource{}
	client := NewGopassClient("")
	r.client = client

	ctx := context.Background()
	schemaReq := ephemeral.SchemaRequest{}
	schemaResp := &ephemeral.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	// Create a mismatched schema/value combination to trigger Config.Get error
	// Use a wrong type in the raw value that doesn't match the schema
	wrongConfigValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.Number, // Wrong type - schema expects String
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, map[string]tftypes.Value{
		"path":   tftypes.NewValue(tftypes.Number, 123), // Wrong type
		"values": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})

	resultRaw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"path":   tftypes.String,
			"values": tftypes.Map{ElementType: tftypes.String},
		},
	}, nil)

	req := ephemeral.OpenRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    wrongConfigValue,
		},
	}
	resp := &ephemeral.OpenResponse{
		Result: tfsdk.EphemeralResultData{
			Schema: schemaResp.Schema,
			Raw:    resultRaw,
		},
	}

	r.Open(ctx, req, resp)

	// Should have an error since Config.Get failed due to type mismatch
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for Config.Get failure due to type mismatch")
	}
}
