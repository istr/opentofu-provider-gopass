// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/api"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// GopassClient wraps the gopass library for secret access.
// It maintains a single store instance for the lifetime of the provider.
type GopassClient struct {
	store       gopass.Store
	storePath   string
	mu          sync.Mutex
	userHomeDir func() (string, error)                          // injectable for testing
	apiNew      func(ctx context.Context) (gopass.Store, error) // injectable for testing
}

// NewGopassClient creates a new gopass client.
// The store is lazily initialized on first access.
// If storePath is non-empty, it will be used instead of the default gopass configuration.
func NewGopassClient(storePath string) *GopassClient {
	return &GopassClient{
		storePath:   storePath,
		userHomeDir: os.UserHomeDir,
		apiNew:      func(ctx context.Context) (gopass.Store, error) { return api.New(ctx) },
	}
}

// ensureStore initializes the gopass store if not already done.
func (c *GopassClient) ensureStore(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store != nil {
		return nil
	}

	tflog.Debug(ctx, "Initializing gopass store", map[string]interface{}{
		"configured_path": c.storePath,
	})

	// If a custom store path is configured, set PASSWORD_STORE_DIR
	// This is the standard way to tell gopass/pass where to find the store
	if c.storePath != "" {
		// Expand ~ if present
		expandedPath := c.storePath
		if strings.HasPrefix(expandedPath, "~/") {
			home, err := c.userHomeDir()
			if err != nil {
				return fmt.Errorf("failed to expand home directory: %w", err)
			}
			expandedPath = filepath.Join(home, expandedPath[2:])
		}

		// Verify the path exists
		if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
			return fmt.Errorf("gopass store not found at configured path: %s\n\n"+
				"Please verify the path exists and contains a valid gopass/pass store, "+
				"or remove the store_path configuration to use gopass defaults", expandedPath)
		}

		tflog.Debug(ctx, "Setting PASSWORD_STORE_DIR", map[string]interface{}{
			"path": expandedPath,
		})
		os.Setenv("PASSWORD_STORE_DIR", expandedPath)
	}

	store, err := c.apiNew(ctx)
	if err != nil {
		// Provide helpful error message
		return c.wrapStoreError(err)
	}

	c.store = store
	tflog.Debug(ctx, "Gopass store initialized successfully")
	return nil
}

// wrapStoreError provides helpful context for common gopass initialization errors.
func (c *GopassClient) wrapStoreError(err error) error {
	errStr := err.Error()

	// Check for common error patterns and provide helpful messages
	if strings.Contains(errStr, "no such file or directory") ||
		strings.Contains(errStr, "does not exist") {
		return fmt.Errorf("gopass store not found: %w\n\n"+
			"No gopass password store was found. Possible solutions:\n\n"+
			"1. Initialize a new store:\n"+
			"   gopass init\n\n"+
			"2. Specify the store location in the provider configuration:\n"+
			"   provider \"gopass\" {\n"+
			"     store_path = \"/home/user/.password-store\"\n"+
			"   }\n\n"+
			"3. Set the PASSWORD_STORE_DIR environment variable:\n"+
			"   export PASSWORD_STORE_DIR=/path/to/store\n\n"+
			"4. Check your gopass configuration:\n"+
			"   cat ~/.config/gopass/config", err)
	}

	if strings.Contains(errStr, "permission denied") {
		return fmt.Errorf("gopass store access denied: %w\n\n"+
			"Unable to access the gopass store due to permission issues.\n"+
			"Please check file permissions on your password store directory.", err)
	}

	if strings.Contains(errStr, "gpg") || strings.Contains(errStr, "GPG") {
		return fmt.Errorf("GPG error during gopass initialization: %w\n\n"+
			"There was a problem with GPG. Please ensure:\n"+
			"- gpg-agent is running\n"+
			"- Your GPG key is available\n"+
			"- If using a hardware token, it is connected", err)
	}

	// Generic error with context
	return fmt.Errorf("failed to initialize gopass store: %w\n\n"+
		"If you have a non-standard gopass configuration, try specifying the store path:\n"+
		"  provider \"gopass\" {\n"+
		"    store_path = \"/path/to/your/password-store\"\n"+
		"  }", err)
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
	err = c.ensureStore(ctx)
	if err != nil {
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

// SetSecret writes a secret to the gopass store.
// The value becomes the first line (password) of the secret.
func (c *GopassClient) SetSecret(ctx context.Context, path, value string) error {
	if err := c.ensureStore(ctx); err != nil {
		return err
	}

	tflog.Debug(ctx, "Writing secret", map[string]interface{}{
		"path": path,
	})

	// Create a new secret object and set the password
	secret := secrets.New()
	secret.SetPassword(value)

	// Set the secret in the store
	if err := c.store.Set(ctx, path, secret); err != nil {
		return fmt.Errorf("failed to write secret %q: %w", path, err)
	}

	tflog.Debug(ctx, "Successfully wrote secret", map[string]interface{}{
		"path": path,
	})

	return nil
}

// RemoveSecret removes a secret from the gopass store.
func (c *GopassClient) RemoveSecret(ctx context.Context, path string) error {
	if err := c.ensureStore(ctx); err != nil {
		return err
	}

	tflog.Debug(ctx, "Removing secret", map[string]interface{}{
		"path": path,
	})

	if err := c.store.Remove(ctx, path); err != nil {
		return fmt.Errorf("failed to remove secret %q: %w", path, err)
	}

	tflog.Debug(ctx, "Successfully removed secret", map[string]interface{}{
		"path": path,
	})

	return nil
}

// SecretExists checks if a secret exists at the given path.
func (c *GopassClient) SecretExists(ctx context.Context, path string) (bool, error) {
	if err := c.ensureStore(ctx); err != nil {
		return false, err
	}

	exists, err := c.store.Get(ctx, path, "latest")
	if err != nil {
		// If the error indicates the secret doesn't exist, that's not an error condition
		// for this function - it just means the secret doesn't exist
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if secret %q exists: %w", path, err)
	}

	return (exists != nil), nil
}

// GetRevisionCount returns the number of revisions for a secret.
// This is used for drift detection - if the count changes, someone modified the secret externally.
//
// Returns:
//   - 0 if the secret doesn't exist
//   - 1 if the secret exists but the backend doesn't support versioning (e.g., some mount types)
//   - N (actual count) if the backend supports versioning (git-backed stores)
//
// Errors from the Revisions() call are logged but not returned - we fall back to
// existence check in that case, as not all backends support revision history.
func (c *GopassClient) GetRevisionCount(ctx context.Context, path string) (int64, error) {
	if err := c.ensureStore(ctx); err != nil {
		return 0, err
	}

	// First check if secret exists
	exists, err := c.store.Get(ctx, path, "latest")
	if err != nil {
		// If the error indicates the secret doesn't exist, that's not an error condition
		// for this function - it just means the secret doesn't exist
		if strings.Contains(err.Error(), "not found") {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to check if secret %q exists: %w", path, err)
	}
	if exists == nil {
		return 0, nil
	}

	// Try to get revision count - not all backends support this.
	// Currently, this is also not yet implemented in the API.
	revisions, err := c.store.Revisions(ctx, path)
	if err != nil {
		// Backend doesn't support revisions or other error
		// Fall back to "1" (exists but no version info)
		tflog.Debug(ctx, "Revisions() not supported or failed, falling back to existence check", map[string]interface{}{
			"path":  path,
			"error": err.Error(),
		})
		return 1, nil
	}

	if len(revisions) == 0 {
		// Secret exists but no revisions reported - treat as 1
		return 1, nil
	}

	return int64(len(revisions)), nil
}
