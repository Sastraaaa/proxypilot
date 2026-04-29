package kiro

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveTokenFilePath(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	path, err := resolveTokenFilePath(baseDir, "nested/kiro-social-user.json")
	if err != nil {
		t.Fatalf("resolveTokenFilePath() error = %v", err)
	}
	want := filepath.Join(baseDir, "nested", "kiro-social-user.json")
	if path != want {
		t.Fatalf("resolveTokenFilePath() = %q, want %q", path, want)
	}

	if _, err := resolveTokenFilePath(baseDir, "../escape.json"); err == nil {
		t.Fatal("resolveTokenFilePath() unexpectedly allowed traversal")
	}
}

func TestFileTokenRepositoryReadTokenFile_PreservesRelativeIDAndSocialAuth(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	tokenPath := filepath.Join(baseDir, "nested", "kiro-social-user.json")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	raw := []byte(`{
  "type": "kiro",
  "auth_method": "social",
  "access_token": "access",
  "refresh_token": "refresh",
  "expires_at": "2026-03-12T00:00:00Z"
}`)
	if err := os.WriteFile(tokenPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	repo := NewFileTokenRepository(baseDir)
	token, err := repo.readTokenFile(tokenPath, baseDir)
	if err != nil {
		t.Fatalf("readTokenFile() error = %v", err)
	}
	if token == nil {
		t.Fatal("readTokenFile() returned nil token")
	}
	if token.ID != filepath.Join("nested", "kiro-social-user.json") {
		t.Fatalf("token.ID = %q", token.ID)
	}
	if token.AuthMethod != "social" {
		t.Fatalf("token.AuthMethod = %q", token.AuthMethod)
	}
}

func TestFileTokenRepositoryUpdateToken_WritesNestedPathInPlace(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	tokenPath := filepath.Join(baseDir, "nested", "kiro-social-user.json")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	raw := []byte(`{"type":"kiro","auth_method":"social","refresh_token":"old"}`)
	if err := os.WriteFile(tokenPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	repo := NewFileTokenRepository(baseDir)
	err := repo.UpdateToken(&Token{
		ID:           filepath.Join("nested", "kiro-social-user.json"),
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		LastVerified: time.Now(),
		AuthMethod:   "social",
	})
	if err != nil {
		t.Fatalf("UpdateToken() error = %v", err)
	}

	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("Stat(nested path) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "kiro-social-user.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected rewritten token at auth root: %v", err)
	}
}

func TestKiroOAuthStartCallbackServer_ResultRemainsAvailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oauth := NewKiroOAuth(nil)
	redirectURI, resultCh, err := oauth.startCallbackServer(ctx, "state-1")
	if err != nil {
		t.Fatalf("startCallbackServer() error = %v", err)
	}

	resp, err := http.Get(redirectURI + "?code=abc&state=state-1")
	if err != nil {
		t.Fatalf("GET callback error = %v", err)
	}
	_ = resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	select {
	case result := <-resultCh:
		if result.Code != "abc" {
			t.Fatalf("result.Code = %q", result.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestSocialAuthStartWebCallbackServer_ResultRemainsAvailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := NewSocialAuthClient(nil)
	redirectURI, resultCh, err := client.startWebCallbackServer(ctx, "state-2")
	if err != nil {
		t.Fatalf("startWebCallbackServer() error = %v", err)
	}

	resp, err := http.Get(redirectURI + "?code=abc&state=state-2")
	if err != nil {
		t.Fatalf("GET callback error = %v", err)
	}
	_ = resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	select {
	case result := <-resultCh:
		if result.Code != "abc" {
			t.Fatalf("result.Code = %q", result.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestSSOOIDCStartAuthCodeCallbackServer_ResultRemainsAvailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := NewSSOOIDCClient(nil)
	redirectURI, resultCh, err := client.startAuthCodeCallbackServer(ctx, "state-3")
	if err != nil {
		t.Fatalf("startAuthCodeCallbackServer() error = %v", err)
	}

	resp, err := http.Get(redirectURI + "?code=abc&state=state-3")
	if err != nil {
		t.Fatalf("GET callback error = %v", err)
	}
	_ = resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	select {
	case result := <-resultCh:
		if result.Code != "abc" {
			t.Fatalf("result.Code = %q", result.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}
