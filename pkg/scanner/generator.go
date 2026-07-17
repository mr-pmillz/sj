package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

func GenerateRequests(body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) {
	if err := GenerateRequestsE(body, client, cfg, writer, resolver); err != nil {
		output.PrintErr("%v", err)
	}
}

func GenerateRequestsE(body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	if err := GenerateRequestsIntoWriterE(body, client, cfg, writer, resolver); err != nil {
		return err
	}
	if cfg.Mode == config.ModeAutomate {
		if err := writer.FinalizeOutput(); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}

// GenerateRequestsIntoWriterE plans and executes one specification without
// finalizing the writer. Batch callers can aggregate multiple specifications
// and publish one valid structured result at the end.
func GenerateRequestsIntoWriterE(body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	return generateRequestsIntoWriterContextE(context.Background(), body, client, cfg, writer, resolver)
}

// GenerateRequestsIntoWriterContextE plans and executes one specification
// without finalizing the writer, and stops promptly when ctx is canceled.
func GenerateRequestsIntoWriterContextE(ctx context.Context, body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	return generateRequestsIntoWriterContextE(ctx, body, client, cfg, writer, resolver)
}

func generateRequestsIntoWriterContextE(ctx context.Context, body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	if openapi.LooksLikeJSSpec(body, cfg.SwaggerURL, cfg.LocalFile, cfg.Format) {
		if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
			body = extracted
		}
	}
	spec, err := openapi.SafelyUnmarshalSpec(body)
	if err != nil {
		return err
	}
	if err := openapi.ValidateReferencePolicy(spec, resolver); err != nil {
		return err
	}
	if err := ConfigureTarget(spec, cfg); err != nil {
		return err
	}
	if cfg.Mode == config.ModeAutomate || cfg.Mode == config.ModePrepare {
		openapi.CheckSecuritySchemes(spec, cfg)
	}
	if cfg.Mode != config.ModeEndpoints {
		openapi.PrintSpecInfo(spec, writer, cfg)
	}
	return buildRequestsFromPathsContextE(ctx, spec, client, cfg, writer, resolver, false)
}

func ConfigureTarget(spec map[string]any, cfg *config.Config) error {
	version, swagger2 := spec["swagger"].(string)
	if swagger2 && strings.HasPrefix(version, "2") {
		return configureSwagger2Target(spec, cfg)
	}
	version, openAPI3 := spec["openapi"].(string)
	if !openAPI3 || !strings.HasPrefix(version, "3") {
		return errorsUnsupportedVersion(version)
	}
	return configureOpenAPI3Target(spec, cfg)
}

func configureSwagger2Target(spec map[string]any, cfg *config.Config) error {
	if !cfg.BasePathExplicit {
		if basePath, ok := spec["basePath"].(string); ok {
			cfg.BasePath = openapi.NormalizeBasePath(basePath)
		}
	}
	if cfg.TargetExplicit {
		return normalizeConfiguredTarget(cfg)
	}
	host, _ := spec["host"].(string)
	if host == "" {
		return targetFromSource(cfg)
	}
	scheme := ""
	if schemes, ok := spec["schemes"].([]any); ok && len(schemes) > 0 {
		scheme, _ = schemes[0].(string)
	}
	if scheme == "" {
		if source, err := url.Parse(cfg.SwaggerURL); err == nil {
			scheme = source.Scheme
		}
	}
	if scheme == "" {
		scheme = "https"
	}
	return setTargetURL(cfg, scheme+"://"+host, false)
}

func configureOpenAPI3Target(spec map[string]any, cfg *config.Config) error {
	if cfg.TargetExplicit {
		return normalizeConfiguredTarget(cfg)
	}
	servers, _ := spec["servers"].([]any)
	if len(servers) == 0 {
		return targetFromSource(cfg)
	}
	server, ok := servers[0].(map[string]any)
	if !ok {
		return fmt.Errorf("first server entry is not an object")
	}
	serverURL, err := expandServerURL(server)
	if err != nil {
		return fmt.Errorf("resolve server URL: %w", err)
	}
	resolved, err := resolveServerURL(serverURL, cfg.SwaggerURL, cfg.APITarget)
	if err != nil {
		return err
	}
	return setTargetURL(cfg, resolved.String(), true)
}

func expandServerURL(server map[string]any) (string, error) {
	raw, _ := server["url"].(string)
	if raw == "" {
		return "", fmt.Errorf("server URL is empty")
	}
	variables, _ := server["variables"].(map[string]any)
	for strings.Contains(raw, "{") {
		start := strings.Index(raw, "{")
		endOffset := strings.Index(raw[start:], "}")
		if endOffset < 0 {
			return "", fmt.Errorf("unclosed server variable in %q", raw)
		}
		end := start + endOffset
		name := raw[start+1 : end]
		definition, _ := variables[name].(map[string]any)
		defaultValue, ok := definition["default"].(string)
		if !ok {
			return "", fmt.Errorf("server variable %q has no string default", name)
		}
		if enum, exists := definition["enum"].([]any); exists && len(enum) > 0 {
			allowed := false
			for _, candidate := range enum {
				if candidate == defaultValue {
					allowed = true
					break
				}
			}
			if !allowed {
				return "", fmt.Errorf("server variable %q default is not listed in its enum", name)
			}
		}
		raw = raw[:start] + defaultValue + raw[end+1:]
	}
	return raw, nil
}

func resolveServerURL(raw, sourceURL, configuredTarget string) (*url.URL, error) {
	serverURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse server URL %q: %w", raw, err)
	}
	if !serverURL.IsAbs() {
		baseRaw := sourceURL
		if baseRaw == "" {
			baseRaw = configuredTarget
		}
		base, baseErr := url.Parse(baseRaw)
		if baseErr != nil || base.Scheme == "" || base.Host == "" {
			return nil, fmt.Errorf("relative server URL %q requires a remote specification URL or --target", raw)
		}
		serverURL = base.ResolveReference(serverURL)
	}
	if serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return nil, fmt.Errorf("server URL must not contain a query or fragment")
	}
	if serverURL.Scheme != "http" && serverURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported server URL scheme %q", serverURL.Scheme)
	}
	if serverURL.Host == "" || serverURL.User != nil {
		return nil, fmt.Errorf("server URL must have a host and no user information")
	}
	return serverURL, nil
}

func setTargetURL(cfg *config.Config, raw string, takeBasePath bool) error {
	target, err := resolveServerURL(raw, cfg.SwaggerURL, "")
	if err != nil {
		return err
	}
	if takeBasePath && !cfg.BasePathExplicit {
		cfg.BasePath = openapi.NormalizeBasePath(target.EscapedPath())
	}
	target.Path = ""
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	cfg.APITarget = target.String()
	return nil
}

func normalizeConfiguredTarget(cfg *config.Config) error {
	target, err := resolveServerURL(cfg.APITarget, cfg.SwaggerURL, "")
	if err != nil {
		return fmt.Errorf("invalid --target: %w", err)
	}
	if !cfg.BasePathExplicit && target.Path != "" && target.Path != "/" {
		cfg.BasePath = openapi.NormalizeBasePath(target.EscapedPath())
	}
	target.Path = ""
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	cfg.APITarget = target.String()
	return nil
}

func targetFromSource(cfg *config.Config) error {
	if cfg.SwaggerURL == "" {
		if cfg.Mode == config.ModeEndpoints {
			return nil
		}
		return fmt.Errorf("no server is defined; use --target for a local specification")
	}
	return setTargetURL(cfg, cfg.SwaggerURL, false)
}

func errorsUnsupportedVersion(version string) error {
	if version == "" {
		return fmt.Errorf("document does not declare a supported Swagger or OpenAPI version")
	}
	return fmt.Errorf("unsupported OpenAPI version %q; supported major versions are Swagger 2 and OpenAPI 3", version)
}
