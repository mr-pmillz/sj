package executor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultSecretResolverReadsEnvironmentAndSecureFiles(t *testing.T) {
	resolver := NewSecretResolver(64)

	t.Run("environment", func(t *testing.T) {
		t.Setenv("SJ_EXECUTOR_TEST_TOKEN", "environment-secret")
		secret, err := resolver.Resolve(t.Context(), "env:SJ_EXECUTOR_TEST_TOKEN")
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if string(secret) != "environment-secret" {
			t.Fatalf("secret = %q", secret)
		}
	})

	t.Run("secure file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secret, err := resolver.Resolve(t.Context(), "file:"+path)
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if string(secret) != "file-secret" {
			t.Fatalf("secret = %q", secret)
		}
	})
}

func TestDefaultSecretResolverRejectsUnsafeReferences(t *testing.T) {
	resolver := NewSecretResolver(8)
	t.Setenv("SJ_EXECUTOR_TEST_LARGE_TOKEN", "123456789")
	t.Setenv("SJ_EXECUTOR_TEST_EMPTY_TOKEN", "")

	for _, test := range []struct {
		name      string
		reference string
		wantError error
	}{
		{name: "unknown scheme", reference: "literal:secret", wantError: ErrSecretReference},
		{name: "empty env name", reference: "env:", wantError: ErrSecretReference},
		{name: "missing env", reference: "env:SJ_EXECUTOR_TEST_MISSING", wantError: ErrSecretUnavailable},
		{name: "oversized env", reference: "env:SJ_EXECUTOR_TEST_LARGE_TOKEN", wantError: ErrSecretTooLarge},
		{name: "empty env", reference: "env:SJ_EXECUTOR_TEST_EMPTY_TOKEN", wantError: ErrSecretUnavailable},
		{name: "invalid env name", reference: "env:BAD=NAME", wantError: ErrSecretReference},
		{name: "relative file", reference: "file:relative-token", wantError: ErrSecretReference},
	} {
		t.Run(test.name, func(t *testing.T) {
			secret, err := resolver.Resolve(t.Context(), test.reference)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Resolve() secret = %q, error = %v, want %v", secret, err, test.wantError)
			}
			if len(secret) != 0 {
				t.Fatalf("secret returned on failure: %q", secret)
			}
		})
	}
}

func TestDefaultSecretResolverRejectsInsecureFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission assertions")
	}
	resolver := NewSecretResolver(64)
	directory := t.TempDir()

	t.Run("group readable", func(t *testing.T) {
		path := filepath.Join(directory, "group-readable")
		if err := os.WriteFile(path, []byte("secret"), 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := resolver.Resolve(t.Context(), "file:"+path)
		if !errors.Is(err, ErrSecretFilePermissions) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "target")
		link := filepath.Join(directory, "link")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := resolver.Resolve(t.Context(), "file:"+link)
		if !errors.Is(err, ErrSecretFileType) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		_, err := resolver.Resolve(t.Context(), "file:"+directory)
		if !errors.Is(err, ErrSecretFileType) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(directory, "oversized")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", 65)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := resolver.Resolve(t.Context(), "file:"+path)
		if !errors.Is(err, ErrSecretTooLarge) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})

	t.Run("empty after line ending removal", func(t *testing.T) {
		path := filepath.Join(directory, "empty")
		if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := resolver.Resolve(t.Context(), "file:"+path)
		if !errors.Is(err, ErrSecretUnavailable) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})
}
