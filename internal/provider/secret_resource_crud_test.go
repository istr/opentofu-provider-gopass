// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestSecretResource_Configure(t *testing.T) {
	r := &SecretResource{}
	client := NewGopassClient("")

	req := resource.ConfigureRequest{
		ProviderData: client,
	}
	resp := &resource.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	if r.client != client {
		t.Error("expected client to be set")
	}
}

func TestSecretResource_Configure_InvalidType(t *testing.T) {
	r := &SecretResource{}

	req := resource.ConfigureRequest{
		ProviderData: "invalid",
	}
	resp := &resource.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error for invalid provider data type")
	}
}

func TestSecretResource_Configure_NilData(t *testing.T) {
	r := &SecretResource{}

	req := resource.ConfigureRequest{
		ProviderData: nil,
	}
	resp := &resource.ConfigureResponse{}

	r.Configure(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestSecretResource_Create(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	// Create the schema for our test
	ctx := context.Background()
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	// Create plan and config values
	planValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"path":             tftypes.NewValue(tftypes.String, "test/secret"),
		"value_wo":         tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"value_wo_version": tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
	})

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"path":             tftypes.NewValue(tftypes.String, "test/secret"),
		"value_wo":         tftypes.NewValue(tftypes.String, "test-password"),
		"value_wo_version": tftypes.NewValue(tftypes.Number, 1),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, nil),
	})

	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planValue,
		},
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
		},
	}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	// Verify secret was stored
	if _, exists := mockStore.secrets["test/secret"]; !exists {
		t.Error("expected secret to be stored in mock store")
	}

	// Verify state was set
	var state SecretResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Errorf("failed to get state: %v", resp.Diagnostics)
	}

	if state.Path.ValueString() != "test/secret" {
		t.Errorf("expected path 'test/secret', got %q", state.Path.ValueString())
	}
	if state.ID.ValueString() != "test/secret" {
		t.Errorf("expected ID 'test/secret', got %q", state.ID.ValueString())
	}
}

func TestSecretResource_Create_NoValueWO(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	planValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"path":             tftypes.NewValue(tftypes.String, "test/secret"),
		"value_wo":         tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"value_wo_version": tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
	})

	configValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"path":             tftypes.NewValue(tftypes.String, "test/secret"),
		"value_wo":         tftypes.NewValue(tftypes.String, nil), // No value provided
		"value_wo_version": tftypes.NewValue(tftypes.Number, nil),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, nil),
	})

	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planValue,
		},
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    configValue,
		},
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
		},
	}

	r.Create(ctx, req, resp)

	// Should succeed but with a warning
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	// Should have warning about no value provided
	hasWarning := false
	for _, diag := range resp.Diagnostics {
		if diag.Summary() == "No value provided" {
			hasWarning = true
			break
		}
	}
	if !hasWarning {
		t.Error("expected warning about no value provided")
	}
}

func TestSecretResource_Read(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	// Add a secret to the mock store
	mockStore.secrets["test/secret"] = newMockSecret("test-password")
	mockStore.revisions["test/secret"] = []string{"1", "2"}

	ctx := context.Background()
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	stateValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, "test/secret"),
		"path":             tftypes.NewValue(tftypes.String, "test/secret"),
		"value_wo":         tftypes.NewValue(tftypes.String, nil),
		"value_wo_version": tftypes.NewValue(tftypes.Number, nil),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, 1),
	})

	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateValue,
		},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateValue,
		},
	}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	// Verify state was updated with new revision count
	var state SecretResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Errorf("failed to get state: %v", resp.Diagnostics)
	}

	if state.RevisionCount.ValueInt64() != 2 {
		t.Errorf("expected revision count 2, got %d", state.RevisionCount.ValueInt64())
	}
}

func TestSecretResource_Read_NotFound(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	stateValue := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":               tftypes.String,
			"path":             tftypes.String,
			"value_wo":         tftypes.String,
			"value_wo_version": tftypes.Number,
			"delete_on_remove": tftypes.Bool,
			"revision_count":   tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, "nonexistent"),
		"path":             tftypes.NewValue(tftypes.String, "nonexistent"),
		"value_wo":         tftypes.NewValue(tftypes.String, nil),
		"value_wo_version": tftypes.NewValue(tftypes.Number, nil),
		"delete_on_remove": tftypes.NewValue(tftypes.Bool, true),
		"revision_count":   tftypes.NewValue(tftypes.Number, 1),
	})

	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateValue,
		},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateValue,
		},
	}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	// State should be removed when secret doesn't exist
	if !resp.State.Raw.IsNull() {
		t.Error("expected state to be removed for non-existent secret")
	}
}

/*
func TestSecretResource_ImportState(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	// Add a secret to the mock store
	mockStore.secrets["test/secret"] = newMockSecret("test-password")
	mockStore.revisions["test/secret"] = []string{"1"}

	ctx := context.Background()

	// Get the schema for the state
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, schemaReq, schemaResp)

	req := resource.ImportStateRequest{
		ID: "test/secret",
	}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
		},
	}

	r.ImportState(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}

	// Verify the imported attributes
	var idVal attr.Value
	resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("id"), &idVal)...)
	if resp.Diagnostics.HasError() {
		t.Errorf("failed to get id: %v", resp.Diagnostics)
	}

	if idString := idVal.(types.String); idString.ValueString() != "test/secret" {
		t.Errorf("expected ID 'test/secret', got %q", idString.ValueString())
	}
}
*/

func TestSecretResource_ImportState_NotFound(t *testing.T) {
	r := &SecretResource{}
	mockStore := newMockStore()
	client := NewGopassClient("")
	client.store = mockStore
	r.client = client

	ctx := context.Background()
	req := resource.ImportStateRequest{
		ID: "nonexistent",
	}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{},
	}

	r.ImportState(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected error for non-existent secret")
	}
}

// Helper function to create mock secrets
func newMockSecret(password string) *mockSecret {
	return &mockSecret{
		password: password,
		fields:   make(map[string]string),
	}
}

// mockSecret implements gopass.Secret interface for testing
type mockSecret struct {
	password string
	fields   map[string]string
}

func (s *mockSecret) Password() string      { return s.password }
func (s *mockSecret) SetPassword(pw string) { s.password = pw }
func (s *mockSecret) Keys() []string {
	keys := make([]string, 0, len(s.fields))
	for k := range s.fields {
		keys = append(keys, k)
	}
	return keys
}
func (s *mockSecret) Get(key string) (string, bool) {
	val, ok := s.fields[key]
	return val, ok
}
func (s *mockSecret) Values(key string) ([]string, bool) {
	val, ok := s.fields[key]
	if !ok {
		return nil, false
	}
	return []string{val}, true
}
func (s *mockSecret) Set(key string, value interface{}) error {
	s.fields[key] = value.(string)
	return nil
}
func (s *mockSecret) Add(key string, value interface{}) error {
	return s.Set(key, value)
}
func (s *mockSecret) Del(key string) bool {
	_, exists := s.fields[key]
	delete(s.fields, key)
	return exists
}
func (s *mockSecret) Body() string { return "" }
func (s *mockSecret) Bytes() []byte {
	result := s.password + "\n"
	for k, v := range s.fields {
		result += k + ": " + v + "\n"
	}
	return []byte(result)
}
