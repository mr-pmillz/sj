package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
)

func loadSpec(ctx context.Context, cfg *config.Config, client *httpclient.Client) ([]byte, error) {
	if err := validateSpecSource(cfg); err != nil {
		return nil, err
	}
	if cfg.SwaggerURL != "" {
		cfg.SpecBaseDir = ""
		body, status, err := client.FetchSpec(ctx, cfg.SwaggerURL)
		if err != nil {
			return nil, fmt.Errorf("fetch specification: %w", err)
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("fetch specification: server returned HTTP %d", status)
		}
		if int64(len(body)) > cfg.MaxSpecBytes {
			return nil, fmt.Errorf("specification exceeds %d-byte limit", cfg.MaxSpecBytes)
		}
		return body, nil
	}

	absPath, err := filepath.Abs(cfg.LocalFile)
	if err != nil {
		return nil, fmt.Errorf("resolve specification path: %w", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open specification: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, cfg.MaxSpecBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read specification: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close specification: %w", closeErr)
	}
	if int64(len(body)) > cfg.MaxSpecBytes {
		return nil, fmt.Errorf("specification exceeds %d-byte limit", cfg.MaxSpecBytes)
	}
	cfg.SpecBaseDir = filepath.Dir(absPath)
	return body, nil
}

func validateSpecSource(cfg *config.Config) error {
	if (cfg.SwaggerURL == "") == (cfg.LocalFile == "") {
		return fmt.Errorf("specify exactly one of --url or --local-file")
	}
	return nil
}

func newHTTPClient(cfg *config.Config) (*httpclient.Client, error) {
	client := httpclient.NewClient(cfg)
	if client.InitErr != nil {
		return nil, client.InitErr
	}
	return client, nil
}
