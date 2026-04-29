package misc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteJSONFileSecure writes JSON to path atomically with restrictive permissions.
// Parent directories are created with 0700 and the file is created with 0600.
func WriteJSONFileSecure(path string, value any, indent bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create directory failed: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	defer func() {
		_ = tmpFile.Close()
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return fmt.Errorf("set temp file permissions failed: %w", err)
	}

	enc := json.NewEncoder(tmpFile)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode json failed: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file failed: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file failed: %w", err)
	}
	cleanup = false
	return nil
}
