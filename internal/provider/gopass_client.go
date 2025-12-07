// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/api"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// GopassClient wraps the gopass library for secret access.
// It maintains a single store instance for the lifetime of the provider.
type GopassClient struct {
	store gopass.Store
	mu    sync.Mutex
}

// NewGopassClient creates a new gopass client.
// The store is lazily initialized on first access.
func NewGopassClient() *GopassClient {
	return &GopassClient{}
}

// ensureStore initializes the gopass store if not already done.
func (c *GopassClient) ensureStore(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store != nil {
		return nil
	}

	tflog.Debug(ctx, "Initializing gopass store")

	store, err := api.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize gopass store: %w", err)
	}

	c.store = store
	tflog.Debug(ctx, "Gopass store initialized")
	return nil
}

// Close closes the gopass store and releases resources.
func (c *GopassClient) Close(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return
	}

	// The gopass API store implements io.Closer through the api.Gopass type
	if closer, ok := c.store.(interface{ Close(context.Context) error }); ok {
		if err := closer.Close(ctx); err != nil {
			tflog.Warn(ctx, "Error closing gopass store", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
	c.store = nil
}

// GetSecret retrieves a single secret by path.
// Returns the password (first line) of the secret.
func (c *GopassClient) GetSecret(ctx context.Context, path string) (string, error) {
	if err := c.ensureStore(ctx); err != nil {
		return "", err
	}

	tflog.Debug(ctx, "Reading secret", map[string]interface{}{
		"path": path,
	})

	// Get secret with "latest" revision
	secret, err := c.store.Get(ctx, path, "latest")
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q: %w", path, err)
	}

	// Password() returns the first line (the actual password)
	password := secret.Password()

	tflog.Debug(ctx, "Successfully read secret", map[string]interface{}{
		"path": path,
	})

	return password, nil
}

// GetSecretFull retrieves a secret with all its key-value pairs.
// Returns the password and a map of additional fields.
func (c *GopassClient) GetSecretFull(ctx context.Context, path string) (password string, fields map[string]string, err error) {
	if err := c.ensureStore(ctx); err != nil {
		return "", nil, err
	}

	secret, err := c.store.Get(ctx, path, "latest")
	if err != nil {
		return "", nil, fmt.Errorf("failed to get secret %q: %w", path, err)
	}

	password = secret.Password()
	fields = make(map[string]string)

	// Get all keys and their values
	for _, key := range secret.Keys() {
		if value, ok := secret.Get(key); ok {
			fields[key] = value
		}
	}

	return password, fields, nil
}

// ListSecrets lists all secrets under a given prefix.
// Returns only immediate children (not recursive).
func (c *GopassClient) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	if err := c.ensureStore(ctx); err != nil {
		return nil, err
	}

	// Normalize prefix
	prefix = strings.TrimSuffix(prefix, "/")

	tflog.Debug(ctx, "Listing secrets", map[string]interface{}{
		"prefix": prefix,
	})

	// List all secrets
	allSecrets, err := c.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Filter to immediate children of prefix
	var results []string
	prefixWithSlash := prefix + "/"

	for _, secretPath := range allSecrets {
		// Must start with prefix
		if !strings.HasPrefix(secretPath, prefixWithSlash) {
			continue
		}

		// Get relative path
		relativePath := strings.TrimPrefix(secretPath, prefixWithSlash)

		// Skip nested paths (only immediate children)
		if strings.Contains(relativePath, "/") {
			continue
		}

		results = append(results, secretPath)
	}

	tflog.Debug(ctx, "Listed secrets", map[string]interface{}{
		"prefix": prefix,
		"count":  len(results),
	})

	return results, nil
}

// GetEnvSecrets reads all immediate child secrets under a path and returns them as a map.
// The map keys are the secret names (relative to prefix), values are the passwords.
func (c *GopassClient) GetEnvSecrets(ctx context.Context, prefix string) (map[string]string, error) {
	secretPaths, err := c.ListSecrets(ctx, prefix)
	if err != nil {
		return nil, err
	}

	prefix = strings.TrimSuffix(prefix, "/")
	result := make(map[string]string)

	for _, fullPath := range secretPaths {
		// Extract key name from path
		key := strings.TrimPrefix(fullPath, prefix+"/")

		// Get the secret value
		value, err := c.GetSecret(ctx, fullPath)
		if err != nil {
			tflog.Warn(ctx, "Failed to read secret, skipping", map[string]interface{}{
				"path":  fullPath,
				"error": err.Error(),
			})
			continue
		}

		result[key] = value
	}

	return result, nil
}
