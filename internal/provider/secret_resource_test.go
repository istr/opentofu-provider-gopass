// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestSecretResource_Metadata(t *testing.T) {
	r := NewSecretResource()
	req := resource.MetadataRequest{
		ProviderTypeName: "gopass",
	}
	resp := &resource.MetadataResponse{}

	r.Metadata(context.Background(), req, resp)

	if resp.TypeName != "gopass_secret" {
		t.Errorf("expected TypeName 'gopass_secret', got %q", resp.TypeName)
	}
}

func TestSecretResource_Schema(t *testing.T) {
	r := NewSecretResource()
	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(context.Background(), req, resp)

	// Verify required attributes exist
	requiredAttrs := []string{"path", "value_wo", "value_wo_version", "delete_on_remove", "id", "revision_count"}
	for _, attr := range requiredAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("expected attribute %q to exist in schema", attr)
		}
	}

	// Verify path is required
	pathAttr := resp.Schema.Attributes["path"]
	if !pathAttr.IsRequired() {
		t.Error("expected 'path' to be required")
	}

	// Verify value_wo is optional and sensitive
	valueWOAttr := resp.Schema.Attributes["value_wo"]
	if !valueWOAttr.IsOptional() {
		t.Error("expected 'value_wo' to be optional")
	}
	if !valueWOAttr.IsSensitive() {
		t.Error("expected 'value_wo' to be sensitive")
	}

	// Verify id is computed
	idAttr := resp.Schema.Attributes["id"]
	if !idAttr.IsComputed() {
		t.Error("expected 'id' to be computed")
	}

	// Verify revision_count is computed
	revCountAttr := resp.Schema.Attributes["revision_count"]
	if !revCountAttr.IsComputed() {
		t.Error("expected 'revision_count' to be computed")
	}
}

func TestSecretResource_ImplementsInterfaces(t *testing.T) {
	r := NewSecretResource()

	// Check that it implements resource.Resource
	if r == nil {
		t.Error("NewSecretResource returned nil")
	}

	// Check ResourceWithConfigure interface
	_, ok := r.(resource.ResourceWithConfigure)
	if !ok {
		t.Error("SecretResource does not implement resource.ResourceWithConfigure")
	}

	// Check ResourceWithImportState interface
	_, ok = r.(resource.ResourceWithImportState)
	if !ok {
		t.Error("SecretResource does not implement resource.ResourceWithImportState")
	}
}
