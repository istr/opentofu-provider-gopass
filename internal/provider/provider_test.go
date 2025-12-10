// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestProvider(t *testing.T) {
	// Basic provider instantiation test
	provider := New("test")()
	if provider == nil {
		t.Fatal("provider is nil")
	}
}

func TestProviderSchema(t *testing.T) {
	// Verify schema is valid
	provider := New("test")()
	if provider == nil {
		t.Fatal("provider is nil")
	}
}

func TestProviderConfigure_SetsEphemeralResourceData(t *testing.T) {
	ctx := context.Background()
	p := &GopassProvider{version: "test"}

	// Get schema first
	schemaReq := provider.SchemaRequest{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(ctx, schemaReq, schemaResp)

	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned errors: %v", schemaResp.Diagnostics)
	}

	// Create empty config using the schema
	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"store_path": tftypes.String,
		},
	}, map[string]tftypes.Value{
		"store_path": tftypes.NewValue(tftypes.String, nil), // null value
	})

	// Create configure request with empty config
	req := provider.ConfigureRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &provider.ConfigureResponse{}

	// Call Configure
	p.Configure(ctx, req, resp)

	// Check for errors
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure() returned errors: %v", resp.Diagnostics)
	}

	// Verify EphemeralResourceData is set (the critical fix!)
	if resp.EphemeralResourceData == nil {
		t.Fatal("Configure() did not set EphemeralResourceData - ephemeral resources will receive nil client and panic")
	}

	// Verify it's the correct type
	client, ok := resp.EphemeralResourceData.(*GopassClient)
	if !ok {
		t.Fatalf("EphemeralResourceData is not *GopassClient, got %T", resp.EphemeralResourceData)
	}

	if client == nil {
		t.Fatal("EphemeralResourceData is nil *GopassClient")
	}

	// Also verify ResourceData and DataSourceData are set for completeness
	if resp.ResourceData == nil {
		t.Error("Configure() did not set ResourceData")
	}
	if resp.DataSourceData == nil {
		t.Error("Configure() did not set DataSourceData")
	}
}

func TestProviderConfigure_WithStorePath(t *testing.T) {
	ctx := context.Background()
	p := &GopassProvider{version: "test"}

	// Get schema first
	schemaReq := provider.SchemaRequest{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(ctx, schemaReq, schemaResp)

	// Create config with store_path set
	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"store_path": tftypes.String,
		},
	}, map[string]tftypes.Value{
		"store_path": tftypes.NewValue(tftypes.String, "/tmp/test-store"),
	})

	req := provider.ConfigureRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &provider.ConfigureResponse{}

	// Call Configure
	p.Configure(ctx, req, resp)

	// Check for errors (we expect none even if store doesn't exist - lazy init)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure() returned errors: %v", resp.Diagnostics)
	}

	// Verify client has store path configured
	client, ok := resp.EphemeralResourceData.(*GopassClient)
	if !ok || client == nil {
		t.Fatal("EphemeralResourceData is not properly set")
	}

	if client.storePath != "/tmp/test-store" {
		t.Errorf("Expected storePath '/tmp/test-store', got '%s'", client.storePath)
	}
}

func TestGopassClient_NewGopassClient(t *testing.T) {
	// Test with empty path
	client := NewGopassClient("")
	if client == nil {
		t.Fatal("NewGopassClient returned nil")
		return
	}
	if client.storePath != "" {
		t.Errorf("Expected empty storePath, got '%s'", client.storePath)
	}

	// Test with path
	client2 := NewGopassClient("/test/path")
	if client2 == nil {
		t.Fatal("NewGopassClient returned nil")
		return
	}
	if client2.storePath != "/test/path" {
		t.Errorf("Expected storePath '/test/path', got '%s'", client2.storePath)
	}
}

// Acceptance tests - require TF_ACC=1 and actual gopass setup
// func TestAccSecretEphemeral_basic(t *testing.T) {
// 	resource.Test(t, resource.TestCase{
// 		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
// 		Steps: []resource.TestStep{
// 			{
// 				Config: `
// 					ephemeral "gopass_secret" "test" {
// 						path = "test/secret"
// 					}
// 				`,
// 			},
// 		},
// 	})
// }
