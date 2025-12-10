// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

// mockStore implements gopass.Store for testing
type mockStore struct {
	secrets    map[string]gopass.Secret
	revisions  map[string][]string
	shouldFail bool
	failMsg    string
}

func newMockStore() *mockStore {
	return &mockStore{
		secrets:   make(map[string]gopass.Secret),
		revisions: make(map[string][]string),
	}
}

func (m *mockStore) Get(ctx context.Context, name, revision string) (gopass.Secret, error) {
	if m.shouldFail {
		return nil, errors.New(m.failMsg)
	}

	secret, exists := m.secrets[name]
	if !exists {
		return nil, fmt.Errorf("secret %q not found", name)
	}
	return secret, nil
}

func (m *mockStore) Set(ctx context.Context, name string, secret gopass.Byter) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}

	if sec, ok := secret.(gopass.Secret); ok {
		m.secrets[name] = sec
		if _, exists := m.revisions[name]; !exists {
			m.revisions[name] = []string{"1"}
		} else {
			revCount := len(m.revisions[name]) + 1
			m.revisions[name] = append(m.revisions[name], fmt.Sprintf("%d", revCount))
		}
	} else {
		// Handle raw bytes by creating a secret
		data := secret.Bytes()
		parsedSecret := secrets.ParseAKV(data)
		m.secrets[name] = parsedSecret
	}

	return nil
}

func (m *mockStore) List(ctx context.Context) ([]string, error) {
	if m.shouldFail {
		return nil, errors.New(m.failMsg)
	}

	var keys []string
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStore) Remove(ctx context.Context, name string) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}

	if _, exists := m.secrets[name]; !exists {
		return fmt.Errorf("secret %q not found", name)
	}

	delete(m.secrets, name)
	delete(m.revisions, name)
	return nil
}

func (m *mockStore) Revisions(ctx context.Context, name string) ([]string, error) {
	if m.shouldFail {
		return nil, errors.New(m.failMsg)
	}

	revs, exists := m.revisions[name]
	if !exists {
		return nil, fmt.Errorf("no revisions for %q", name)
	}
	return revs, nil
}

func (m *mockStore) RemoveAll(ctx context.Context, prefix string) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}

	for name := range m.secrets {
		if strings.HasPrefix(name, prefix) {
			delete(m.secrets, name)
			delete(m.revisions, name)
		}
	}
	return nil
}

func (m *mockStore) Rename(ctx context.Context, src, dest string) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}

	secret, exists := m.secrets[src]
	if !exists {
		return fmt.Errorf("secret %q not found", src)
	}

	m.secrets[dest] = secret
	m.revisions[dest] = m.revisions[src]
	delete(m.secrets, src)
	delete(m.revisions, src)
	return nil
}

func (m *mockStore) String() string {
	return "mock-store"
}

func (m *mockStore) Sync(ctx context.Context) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}
	return nil
}

func (m *mockStore) Close(ctx context.Context) error {
	if m.shouldFail {
		return errors.New(m.failMsg)
	}
	return nil
}

func TestGopassClient_Constructor(t *testing.T) {
	// Test with empty path
	client := NewGopassClient("")
	if client == nil {
		t.Fatal("expected client to be created")
		return
	}

	if client.storePath != "" {
		t.Errorf("expected empty store path, got %q", client.storePath)
	}

	if client.store != nil {
		t.Error("expected store to be nil initially")
	}

	// Test with custom path
	client2 := NewGopassClient("/test/path")

	if client2 == nil {
		t.Fatal("expected client to be created")
		return
	}

	if client2.storePath != "/test/path" {
		t.Errorf("expected store path '/test/path', got %q", client2.storePath)
	}

	if client2.store != nil {
		t.Error("expected store to be nil initially")
	}
}

func TestGopassClient_SetSecret(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	err := client.SetSecret(ctx, "test/secret", "password123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify secret was stored
	secret, exists := mockStore.secrets["test/secret"]
	if !exists {
		t.Error("expected secret to be stored")
	}

	if secret.Password() != "password123" {
		t.Errorf("expected password 'password123', got %q", secret.Password())
	}
}

func TestGopassClient_SetSecret_StoreFailure(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "store error"
	client.store = mockStore

	ctx := context.Background()

	err := client.SetSecret(ctx, "test/secret", "password123")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to write secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

func TestGopassClient_GetSecret(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Create a test secret
	secret := secrets.New()
	secret.SetPassword("test-password")
	mockStore.secrets["test/path"] = secret

	ctx := context.Background()

	password, err := client.GetSecret(ctx, "test/path")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if password != "test-password" {
		t.Errorf("expected password 'test-password', got %q", password)
	}
}

func TestGopassClient_GetSecret_NotFound(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	_, err := client.GetSecret(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to get secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

func TestGopassClient_GetSecretFull(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Create a test secret with key-value pairs
	secret := secrets.New()
	secret.SetPassword("test-password")
	secret.Set("username", "testuser")
	secret.Set("url", "https://example.com")
	mockStore.secrets["test/path"] = secret

	ctx := context.Background()

	password, fields, err := client.GetSecretFull(ctx, "test/path")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if password != "test-password" {
		t.Errorf("expected password 'test-password', got %q", password)
	}

	expectedFields := map[string]string{
		"username": "testuser",
		"url":      "https://example.com",
	}

	for key, expectedValue := range expectedFields {
		if value, exists := fields[key]; !exists {
			t.Errorf("expected field %q to exist", key)
		} else if value != expectedValue {
			t.Errorf("expected field %q to be %q, got %q", key, expectedValue, value)
		}
	}
}

func TestGopassClient_ListSecrets(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add test secrets
	secret := secrets.New()
	secret.SetPassword("pass1")
	mockStore.secrets["env/test/secret1"] = secret
	mockStore.secrets["env/test/secret2"] = secret
	mockStore.secrets["env/test/sub/secret3"] = secret
	mockStore.secrets["other/secret4"] = secret

	ctx := context.Background()

	results, err := client.ListSecrets(ctx, "env/test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expectedSecrets := []string{"env/test/secret1", "env/test/secret2"}
	if len(results) != len(expectedSecrets) {
		t.Errorf("expected %d secrets, got %d", len(expectedSecrets), len(results))
	}

	for _, expected := range expectedSecrets {
		found := false
		for _, result := range results {
			if result == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected to find secret %q in results", expected)
		}
	}
}

func TestGopassClient_GetEnvSecrets(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add test secrets
	secret1 := secrets.New()
	secret1.SetPassword("value1")
	mockStore.secrets["env/test/KEY1"] = secret1

	secret2 := secrets.New()
	secret2.SetPassword("value2")
	mockStore.secrets["env/test/KEY2"] = secret2

	ctx := context.Background()

	envVars, err := client.GetEnvSecrets(ctx, "env/test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
	}

	if len(envVars) != len(expected) {
		t.Errorf("expected %d env vars, got %d", len(expected), len(envVars))
	}

	for key, expectedValue := range expected {
		if value, exists := envVars[key]; !exists {
			t.Errorf("expected env var %q to exist", key)
		} else if value != expectedValue {
			t.Errorf("expected env var %q to be %q, got %q", key, expectedValue, value)
		}
	}
}

func TestGopassClient_RemoveSecret(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add a test secret
	secret := secrets.New()
	secret.SetPassword("test")
	mockStore.secrets["test/secret"] = secret

	ctx := context.Background()

	err := client.RemoveSecret(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify secret was removed
	if _, exists := mockStore.secrets["test/secret"]; exists {
		t.Error("expected secret to be removed")
	}
}

func TestGopassClient_RemoveSecret_NotFound(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	err := client.RemoveSecret(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_SecretExists(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add a test secret
	secret := secrets.New()
	secret.SetPassword("test")
	mockStore.secrets["test/secret"] = secret

	ctx := context.Background()

	// Test existing secret
	exists, err := client.SecretExists(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected secret to exist")
	}

	// Test non-existing secret - should not return an error, just false
	exists, err = client.SecretExists(ctx, "nonexistent")
	if err != nil {
		t.Errorf("unexpected error for non-existent secret: %v", err)
	}
	if exists {
		t.Error("expected secret to not exist")
	}
}

func TestGopassClient_GetRevisionCount(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add a test secret with revisions
	secret := secrets.New()
	secret.SetPassword("test")
	mockStore.secrets["test/secret"] = secret
	mockStore.revisions["test/secret"] = []string{"1", "2", "3"}

	ctx := context.Background()

	count, err := client.GetRevisionCount(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if count != 3 {
		t.Errorf("expected revision count 3, got %d", count)
	}
}

func TestGopassClient_GetRevisionCount_NotFound(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	count, err := client.GetRevisionCount(ctx, "nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if count != 0 {
		t.Errorf("expected revision count 0 for non-existent secret, got %d", count)
	}
}

func TestGopassClient_GetRevisionCount_NoRevisionsSupported(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add a secret but make revisions fail
	secret := secrets.New()
	secret.SetPassword("test")
	mockStore.secrets["test/secret"] = secret

	// Override the Revisions method to fail when called directly in GetRevisionCount
	originalRevisions := mockStore.revisions["test/secret"]
	delete(mockStore.revisions, "test/secret")

	ctx := context.Background()

	count, err := client.GetRevisionCount(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should fall back to 1 when revisions are not supported
	if count != 1 {
		t.Errorf("expected revision count 1 (fallback), got %d", count)
	}

	// Restore
	mockStore.revisions["test/secret"] = originalRevisions
}

func TestGopassClient_Close(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	// Should not panic and should clear the store
	client.Close(ctx)

	if client.store != nil {
		t.Error("expected store to be nil after close")
	}
}

func TestGopassClient_WrapStoreError(t *testing.T) {
	client := NewGopassClient("")

	testCases := []struct {
		name           string
		inputError     error
		expectedSubstr string
	}{
		{
			name:           "file not found",
			inputError:     errors.New("no such file or directory"),
			expectedSubstr: "gopass store not found",
		},
		{
			name:           "does not exist",
			inputError:     errors.New("does not exist"),
			expectedSubstr: "gopass store not found",
		},
		{
			name:           "permission denied",
			inputError:     errors.New("permission denied"),
			expectedSubstr: "gopass store access denied",
		},
		{
			name:           "gpg error",
			inputError:     errors.New("gpg: error"),
			expectedSubstr: "GPG error during gopass initialization",
		},
		{
			name:           "generic error",
			inputError:     errors.New("some other error"),
			expectedSubstr: "failed to initialize gopass store",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wrappedErr := client.wrapStoreError(tc.inputError)
			if !strings.Contains(wrappedErr.Error(), tc.expectedSubstr) {
				t.Errorf("expected error to contain %q, got %q", tc.expectedSubstr, wrappedErr.Error())
			}
		})
	}
}

func TestGopassClient_EnsureStore_WithStorePath(t *testing.T) {
	// Save and restore environment variable
	originalEnv := os.Getenv("PASSWORD_STORE_DIR")
	defer func() {
		if originalEnv != "" {
			os.Setenv("PASSWORD_STORE_DIR", originalEnv)
		} else {
			os.Unsetenv("PASSWORD_STORE_DIR")
		}
	}()

	// Create a temporary directory for testing
	tempDir := os.TempDir()

	client := NewGopassClient(tempDir)

	ctx := context.Background()

	// This will fail because we don't have a real gopass store, but we can test the path expansion logic
	err := client.ensureStore(ctx)
	if err == nil {
		t.Errorf("expected error due to missing gopass store")
	}

	// Check that PASSWORD_STORE_DIR was set
	envValue := os.Getenv("PASSWORD_STORE_DIR")
	if envValue != tempDir {
		t.Errorf("expected PASSWORD_STORE_DIR to be %q, got %q", tempDir, envValue)
	}
}

func TestGopassClient_EnsureStore_HomeExpansion(t *testing.T) {
	// Save and restore environment variable
	originalEnv := os.Getenv("PASSWORD_STORE_DIR")
	defer func() {
		if originalEnv != "" {
			os.Setenv("PASSWORD_STORE_DIR", originalEnv)
		} else {
			os.Unsetenv("PASSWORD_STORE_DIR")
		}
	}()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot get home directory: %v", err)
	}

	// Create a temporary directory that exists for testing path expansion
	testDir := homeDir + "/test-path-temp"
	err = os.MkdirAll(testDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	client := NewGopassClient("~/test-path-temp")

	ctx := context.Background()

	// This will still fail because we don't have a real gopass store,
	// but it should set the environment variable first
	err = client.ensureStore(ctx)
	if err == nil {
		t.Error("expected error due to missing gopass store")
	}

	expectedPath := homeDir + "/test-path-temp"
	envValue := os.Getenv("PASSWORD_STORE_DIR")
	if envValue != expectedPath {
		t.Errorf("expected PASSWORD_STORE_DIR to be %q, got %q", expectedPath, envValue)
	}
}

func TestGopassClient_EnsureStore_NonExistentPath(t *testing.T) {
	client := NewGopassClient("/definitely/does/not/exist")

	ctx := context.Background()

	err := client.ensureStore(ctx)
	if err == nil {
		t.Error("expected error for non-existent path")
	}

	if !strings.Contains(err.Error(), "gopass store not found at configured path") {
		t.Errorf("expected specific error message, got %v", err)
	}
}

func TestGopassClient_EnsureStore_AlreadyInitialized(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	// Should return immediately without error since store is already set
	err := client.ensureStore(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Store should still be the same
	if client.store != mockStore {
		t.Error("store was unexpectedly changed")
	}
}

func TestGopassClient_Close_NilStore(t *testing.T) {
	client := NewGopassClient("")
	client.store = nil

	ctx := context.Background()

	// Should not panic when store is nil
	client.Close(ctx)

	if client.store != nil {
		t.Error("store should remain nil")
	}
}

func TestGopassClient_Close_WithCloseError(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "close error"
	client.store = mockStore

	ctx := context.Background()

	// Should not panic even if Close fails (it just logs warning)
	client.Close(ctx)

	// Store should still be set to nil after Close
	if client.store != nil {
		t.Error("store should be nil after Close")
	}
}

func TestGopassClient_GetSecretFull_NotFound(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	ctx := context.Background()

	_, _, err := client.GetSecretFull(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to get secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

func TestGopassClient_ListSecrets_Error(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "list error"
	client.store = mockStore

	ctx := context.Background()

	_, err := client.ListSecrets(ctx, "test/prefix")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to list secrets") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

// mockStoreWithSelectiveFailure allows failing only specific operations
type mockStoreWithSelectiveFailure struct {
	*mockStore
	failOnGet map[string]bool
}

func newMockStoreWithSelectiveFailure() *mockStoreWithSelectiveFailure {
	return &mockStoreWithSelectiveFailure{
		mockStore: newMockStore(),
		failOnGet: make(map[string]bool),
	}
}

func (m *mockStoreWithSelectiveFailure) Get(ctx context.Context, name, revision string) (gopass.Secret, error) {
	if m.failOnGet[name] {
		return nil, fmt.Errorf("selective failure for %q", name)
	}
	return m.mockStore.Get(ctx, name, revision)
}

func TestGopassClient_GetEnvSecrets_PartialFailure(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStoreWithSelectiveFailure()
	client.store = mockStore

	// Add test secrets
	secret1 := secrets.New()
	secret1.SetPassword("value1")
	mockStore.secrets["env/test/KEY1"] = secret1

	secret2 := secrets.New()
	secret2.SetPassword("value2")
	mockStore.secrets["env/test/KEY2"] = secret2

	// Make KEY2 fail when trying to read its value
	mockStore.failOnGet["env/test/KEY2"] = true

	ctx := context.Background()

	envVars, err := client.GetEnvSecrets(ctx, "env/test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should only have KEY1 since KEY2 failed and was skipped
	if len(envVars) != 1 {
		t.Errorf("expected 1 env var, got %d", len(envVars))
	}

	if value, exists := envVars["KEY1"]; !exists || value != "value1" {
		t.Errorf("expected KEY1=value1, got %v", envVars)
	}
}

func TestGopassClient_SecretExists_OtherError(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "database connection error"
	client.store = mockStore

	ctx := context.Background()

	_, err := client.SecretExists(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to check if secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

func TestGopassClient_GetRevisionCount_EmptyRevisions(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	client.store = mockStore

	// Add a secret with empty revisions array
	secret := secrets.New()
	secret.SetPassword("test")
	mockStore.secrets["test/secret"] = secret
	mockStore.revisions["test/secret"] = []string{} // Empty but not nil

	ctx := context.Background()

	count, err := client.GetRevisionCount(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should return 1 when revisions array is empty (fallback)
	if count != 1 {
		t.Errorf("expected revision count 1, got %d", count)
	}
}

func TestGopassClient_GetRevisionCount_OtherError(t *testing.T) {
	client := NewGopassClient("")
	mockStore := newMockStore()
	mockStore.shouldFail = true
	mockStore.failMsg = "database error"
	client.store = mockStore

	ctx := context.Background()

	_, err := client.GetRevisionCount(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}

	if !strings.Contains(err.Error(), "failed to check if secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}

// mockStoreReturningNilSecret returns nil secret without error
type mockStoreReturningNilSecret struct {
	*mockStore
}

func (m *mockStoreReturningNilSecret) Get(ctx context.Context, name, revision string) (gopass.Secret, error) {
	// Return nil without error - edge case
	return nil, nil
}

func TestGopassClient_GetRevisionCount_NilSecret(t *testing.T) {
	client := NewGopassClient("")
	mockStore := &mockStoreReturningNilSecret{mockStore: newMockStore()}
	client.store = mockStore

	ctx := context.Background()

	count, err := client.GetRevisionCount(ctx, "test/secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should return 0 when secret is nil
	if count != 0 {
		t.Errorf("expected revision count 0, got %d", count)
	}
}

// Test ensureStore error propagation for all methods
// These tests use a non-existent path to trigger ensureStore failure

func TestGopassClient_GetSecret_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")
	// store is nil, ensureStore will be called and fail

	ctx := context.Background()

	_, err := client.GetSecret(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_GetSecretFull_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	_, _, err := client.GetSecretFull(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_ListSecrets_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	_, err := client.ListSecrets(ctx, "test/prefix")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_GetEnvSecrets_ListError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	_, err := client.GetEnvSecrets(ctx, "test/prefix")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_SetSecret_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	err := client.SetSecret(ctx, "test/secret", "password")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_RemoveSecret_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	err := client.RemoveSecret(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_SecretExists_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	_, err := client.SecretExists(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}
}

func TestGopassClient_GetRevisionCount_EnsureStoreError(t *testing.T) {
	client := NewGopassClient("/nonexistent/path/for/test")

	ctx := context.Background()

	_, err := client.GetRevisionCount(ctx, "test/secret")
	if err == nil {
		t.Error("expected error but got none")
	}
}
