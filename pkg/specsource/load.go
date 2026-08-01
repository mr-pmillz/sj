// Package specsource loads bounded Swagger/OpenAPI documents from local files or URLs.
package specsource

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

// Load reads the single source configured in cfg and updates SpecBaseDir for
// confined local reference resolution.
func Load(ctx context.Context, cfg *config.Config, client *httpclient.Client) ([]byte, error) {
	body, _, _, err := LoadWithMetadata(ctx, cfg, client)
	return body, err
}

// LoadWithMetadata returns the HTTP outcome for remote specifications so batch
// callers can enforce one origin-level rate and transport circuit across both
// specification fetches and generated operation requests.
func LoadWithMetadata(
	ctx context.Context,
	cfg *config.Config,
	client *httpclient.Client,
) ([]byte, int, httpclient.ResponseMetadata, error) {
	if err := Validate(cfg); err != nil {
		return nil, 0, httpclient.ResponseMetadata{}, err
	}
	if cfg.SwaggerURL != "" {
		cfg.SpecBaseDir = ""
		body, status, metadata, err := client.FetchSpecWithMetadata(ctx, cfg.SwaggerURL)
		if err != nil {
			return nil, status, metadata, fmt.Errorf("fetch specification: %w", err)
		}
		if status < 200 || status >= 300 {
			return nil, status, metadata, fmt.Errorf("fetch specification: server returned HTTP %d", status)
		}
		if int64(len(body)) > cfg.MaxSpecBytes {
			return nil, status, metadata, fmt.Errorf("specification exceeds %d-byte limit", cfg.MaxSpecBytes)
		}
		return body, status, metadata, nil
	}

	absPath, err := filepath.Abs(cfg.LocalFile)
	if err != nil {
		return nil, 0, httpclient.ResponseMetadata{}, fmt.Errorf("resolve specification path: %w", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, 0, httpclient.ResponseMetadata{}, fmt.Errorf("open specification: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, cfg.MaxSpecBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, 0, httpclient.ResponseMetadata{}, fmt.Errorf("read specification: %w", readErr)
	}
	if closeErr != nil {
		return nil, 0, httpclient.ResponseMetadata{}, fmt.Errorf("close specification: %w", closeErr)
	}
	if int64(len(body)) > cfg.MaxSpecBytes {
		return nil, 0, httpclient.ResponseMetadata{}, fmt.Errorf("specification exceeds %d-byte limit", cfg.MaxSpecBytes)
	}
	cfg.SpecBaseDir = filepath.Dir(absPath)
	return body, 0, httpclient.ResponseMetadata{}, nil
}

// Validate requires exactly one configured remote or local source.
func Validate(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("specification configuration is required")
	}
	if (cfg.SwaggerURL == "") == (cfg.LocalFile == "") {
		return fmt.Errorf("specify exactly one of URL or local file")
	}
	return nil
}
