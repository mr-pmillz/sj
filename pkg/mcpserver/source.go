package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/specsource"
)

func (service *service) loadSource(ctx context.Context, source sourceInput) ([]byte, *config.Config, error) {
	if err := checkContext(ctx, "load specification"); err != nil {
		return nil, nil, err
	}
	if !validFormat(source.Format) {
		return nil, nil, fmt.Errorf("unsupported input format %q; use json, yaml, yml, or js", source.Format)
	}
	configured := 0
	for _, value := range []string{source.URL, source.Document, source.LocalFile} {
		if value != "" {
			configured++
		}
	}
	if configured != 1 {
		return nil, nil, fmt.Errorf("specify exactly one source: url, document, or local_file")
	}

	cfg := service.config()
	if source.Format != "" {
		cfg.Format = strings.ToLower(source.Format)
	}
	switch {
	case source.Document != "":
		if int64(len(source.Document)) > cfg.MaxSpecBytes {
			return nil, nil, fmt.Errorf("inline specification exceeds %d-byte limit", cfg.MaxSpecBytes)
		}
		cfg.SpecBaseDir = ""
		return []byte(source.Document), cfg, nil
	case source.URL != "":
		if err := service.policy.checkURL("specification", source.URL); err != nil {
			return nil, nil, err
		}
		cfg.SwaggerURL = source.URL
	case source.LocalFile != "":
		if !service.policy.allowLocalFiles {
			return nil, nil, fmt.Errorf("local file access is disabled by the MCP server")
		}
		cfg.LocalFile = source.LocalFile
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid tool configuration: %w", err)
	}
	client, err := service.newClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize HTTP client: %w", err)
	}
	body, err := specsource.Load(ctx, cfg, client)
	if err != nil {
		return nil, nil, err
	}
	return body, cfg, nil
}

func (service *service) parseSource(ctx context.Context, source sourceInput) (map[string]any, *config.Config, *openapi.Resolver, error) {
	body, cfg, err := service.loadSource(ctx, source)
	if err != nil {
		return nil, nil, nil, err
	}
	if openapi.LooksLikeJSSpec(body, cfg.SwaggerURL, cfg.LocalFile, cfg.Format) {
		if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
			body = extracted
		}
	}
	spec, err := openapi.SafelyUnmarshalSpec(body)
	if err != nil {
		return nil, nil, nil, err
	}
	resolver := openapi.NewResolver(cfg.SpecBaseDir)
	if err := openapi.ValidateReferencePolicy(spec, resolver); err != nil {
		return nil, nil, nil, err
	}
	return spec, cfg, resolver, nil
}
