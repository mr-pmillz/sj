package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const defaultMaxSecretBytes int64 = 16 * 1024

type defaultSecretResolver struct {
	maxBytes int64
}

func NewSecretResolver(maxBytes int64) SecretResolver {
	if maxBytes <= 0 {
		maxBytes = defaultMaxSecretBytes
	}
	return &defaultSecretResolver{maxBytes: maxBytes}
}

func (resolver *defaultSecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scheme, value, valid := parseSecretReference(reference)
	if !valid {
		return nil, ErrSecretReference
	}

	switch scheme {
	case "env":
		return resolver.environment(value)
	case "file":
		return resolver.file(ctx, value)
	default:
		return nil, ErrSecretReference
	}
}

func parseSecretReference(reference string) (string, string, bool) {
	scheme, value, found := strings.Cut(reference, ":")
	if !found || value == "" {
		return "", "", false
	}
	switch scheme {
	case "env":
		return scheme, value, validEnvironmentName(value)
	case "file":
		return scheme, value, filepath.IsAbs(value)
	default:
		return "", "", false
	}
}

func validEnvironmentName(name string) bool {
	for index, character := range name {
		if character == '_' || character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return name != ""
}

func (resolver *defaultSecretResolver) environment(name string) ([]byte, error) {
	value, found := os.LookupEnv(name)
	if !found {
		return nil, ErrSecretUnavailable
	}
	if value == "" {
		return nil, ErrSecretUnavailable
	}
	if int64(len(value)) > resolver.maxBytes {
		return nil, ErrSecretTooLarge
	}
	return []byte(value), nil
}

func (resolver *defaultSecretResolver) file(ctx context.Context, path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, sanitized("resolve secret file", ErrSecretUnavailable, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, ErrSecretFileType
	}
	if before.Mode().Perm()&0o077 != 0 {
		return nil, ErrSecretFilePermissions
	}
	if before.Size() > resolver.maxBytes {
		return nil, ErrSecretTooLarge
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, sanitized("open secret file", ErrSecretUnavailable, err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, sanitized("stat secret file", ErrSecretUnavailable, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, ErrSecretFileType
	}
	if after.Mode().Perm()&0o077 != 0 {
		return nil, ErrSecretFilePermissions
	}

	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, resolver.maxBytes+1))
	if err != nil {
		return nil, sanitized("read secret file", ErrSecretUnavailable, err)
	}
	if int64(len(data)) > resolver.maxBytes {
		return nil, ErrSecretTooLarge
	}
	data = trimOneLineEnding(data)
	if len(data) == 0 {
		return nil, ErrSecretUnavailable
	}
	return data, nil
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

type classifiedError struct {
	message string
	classes []error
}

func (err *classifiedError) Error() string { return err.message }

func (err *classifiedError) Unwrap() []error { return err.classes }

func sanitized(operation string, class error, cause error) error {
	return &classifiedError{
		message: fmt.Sprintf("%s: %s", operation, class.Error()),
		classes: []error{class, cause},
	}
}
