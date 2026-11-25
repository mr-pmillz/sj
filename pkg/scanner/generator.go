package scanner

import (
	"context"
	"errors"
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
	return generateRequestsIntoWriterContextWithCircuitE(
		ctx, body, client, cfg, writer, resolver, NewTargetCircuit(),
	)
}

func generateRequestsIntoWriterContextE(ctx context.Context, body []byte, client *httpclient.Client, cfg *config.Config, writer *output.Writer, resolver *openapi.Resolver) error {
	return generateRequestsIntoWriterContextWithCircuitE(
		ctx, body, client, cfg, writer, resolver, NewTargetCircuit(),
	)
}

func GenerateRequestsIntoWriterWithCircuitContextE(
	ctx context.Context,
	body []byte,
	client *httpclient.Client,
	cfg *config.Config,
	writer *output.Writer,
	resolver *openapi.Resolver,
	circuit *TargetCircuit,
) error {
	return generateRequestsIntoWriterContextWithCircuitE(
		ctx, body, client, cfg, writer, resolver, circuit,
	)
}

func generateRequestsIntoWriterContextWithCircuitE(
	ctx context.Context,
	body []byte,
	client *httpclient.Client,
	cfg *config.Config,
	writer *output.Writer,
	resolver *openapi.Resolver,
	circuit *TargetCircuit,
) error {
	spec, err := readSpecification(body, cfg.SwaggerURL, cfg.LocalFile, cfg.Format, resolver)
	if err != nil {
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
	return buildRequestsFromPathsContextWithCircuitE(ctx, spec, client, cfg, writer, resolver, false, circuit)
}

// readSpecification reads a fetched document the way the test stage does
// before it configures a target: a JavaScript bundle is unwrapped only when
// its source, --format or opening bytes say it is JavaScript, the document is
// parsed, and its references must pass the reference policy.
func readSpecification(body []byte, swaggerURL, localFile, format string, resolver *openapi.Resolver) (map[string]any, error) {
	if openapi.LooksLikeJSSpec(body, swaggerURL, localFile, format) {
		if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
			body = extracted
		}
	}
	spec, err := openapi.SafelyUnmarshalSpec(body)
	if err != nil {
		return nil, err
	}
	if err := openapi.ValidateReferencePolicy(spec, resolver); err != nil {
		return nil, err
	}
	return spec, nil
}

// ConfigureTarget sets the run's API target and base path for spec. An
// explicit --target or --base-path wins; otherwise both come from the
// document through resolveDocumentBase, which discovery also calls
// (DocumentAPIBase), so the two stages name the same API base.
func ConfigureTarget(spec map[string]any, cfg *config.Config) error {
	swagger2, err := specificationKind(spec)
	if err != nil {
		return err
	}
	if cfg.TargetExplicit {
		if swagger2 && !cfg.BasePathExplicit {
			if basePath, named := swagger2BasePath(spec); named {
				cfg.BasePath = basePath
			}
		}
		return normalizeConfiguredTarget(cfg)
	}
	base, err := resolveDocumentBase(spec, swagger2, cfg.SwaggerURL, cfg.APITarget)
	if base.namesBasePath && !cfg.BasePathExplicit {
		cfg.BasePath = base.basePath
	}
	if errors.Is(err, errNoDocumentServer) && cfg.Mode == config.ModeEndpoints {
		// Listing the endpoints of a local document needs no target.
		return nil
	}
	if err != nil {
		return err
	}
	cfg.APITarget = base.origin
	return nil
}

// DocumentAPIBase returns the base URL the test stage sends the requests of
// a document to when neither --target nor --base-path is set. body is what
// documentURL served; it is read as the test stage reads a fetched document
// (readSpecification, with the default --format and no local reference
// directory), and the base is resolved by the code ConfigureTarget uses: the
// first OpenAPI 3 server (variables at their defaults, a relative URL
// resolved against documentURL), the Swagger 2 host with its first scheme and
// its basePath, or the document's own origin when it names neither. The
// result is the scheme, host, port when it is not the scheme's default, and
// base path, with no trailing slash, user information, query or fragment. It
// returns an error wherever the test stage would refuse the document or
// could not configure a target for it.
func DocumentAPIBase(body []byte, documentURL string) (string, error) {
	spec, err := readSpecification(body, documentURL, "", "", openapi.NewResolver(""))
	if err != nil {
		return "", err
	}
	return documentSpecAPIBase(spec, documentURL)
}

// documentSpecAPIBase is DocumentAPIBase for a parsed document.
func documentSpecAPIBase(spec map[string]any, documentURL string) (string, error) {
	swagger2, err := specificationKind(spec)
	if err != nil {
		return "", err
	}
	base, err := resolveDocumentBase(spec, swagger2, documentURL, "")
	if err != nil {
		return "", err
	}
	return base.url()
}

// documentBase is the API base a specification names for its requests.
type documentBase struct {
	// origin is scheme://host[:port] exactly as the test stage sends to it.
	origin string
	// basePath is the normalized, escaped base path; "" is the root.
	basePath string
	// namesBasePath reports whether the document set the base path: an
	// OpenAPI 3 server, or a Swagger 2 basePath member.
	namesBasePath bool
}

// url joins the origin and base path, leaving out a port that is the
// scheme's default (the same endpoint either way).
func (base documentBase) url() (string, error) {
	origin, err := url.Parse(base.origin)
	if err != nil {
		return "", fmt.Errorf("parse API origin: %w", err)
	}
	if port := origin.Port(); port == "" || port == defaultPorts[origin.Scheme] {
		origin.Host = strings.TrimSuffix(origin.Host, ":"+port)
	}
	return origin.String() + base.basePath, nil
}

var defaultPorts = map[string]string{"http": "80", "https": "443"}

var errNoDocumentServer = errors.New("no server is defined; use --target for a local specification")

// specificationKind reports whether spec is a Swagger 2 document, or refuses
// it when it is neither Swagger 2 nor OpenAPI 3.
func specificationKind(spec map[string]any) (bool, error) {
	if version, ok := spec["swagger"].(string); ok && strings.HasPrefix(version, "2") {
		return true, nil
	}
	version, ok := spec["openapi"].(string)
	if !ok || !strings.HasPrefix(version, "3") {
		return false, errorsUnsupportedVersion(version)
	}
	return false, nil
}

// resolveDocumentBase resolves the API base a specification names when no
// target is configured. documentURL is the document's own URL ("" for a
// local file); fallbackTarget resolves a relative OpenAPI 3 server only when
// there is no document URL. On a Swagger 2 error the returned base still
// carries the document's basePath.
func resolveDocumentBase(spec map[string]any, swagger2 bool, documentURL, fallbackTarget string) (documentBase, error) {
	if swagger2 {
		return resolveSwagger2Base(spec, documentURL)
	}
	return resolveOpenAPI3Base(spec, documentURL, fallbackTarget)
}

func resolveSwagger2Base(spec map[string]any, documentURL string) (documentBase, error) {
	var base documentBase
	base.basePath, base.namesBasePath = swagger2BasePath(spec)
	host, _ := spec["host"].(string)
	if host == "" {
		origin, err := documentOrigin(documentURL)
		base.origin = origin
		return base, err
	}
	scheme := ""
	if schemes, ok := spec["schemes"].([]any); ok && len(schemes) > 0 {
		scheme, _ = schemes[0].(string)
	}
	if scheme == "" {
		if source, err := url.Parse(documentURL); err == nil {
			scheme = source.Scheme
		}
	}
	if scheme == "" {
		scheme = "https"
	}
	origin, _, err := splitServerURL(scheme+"://"+host, documentURL)
	base.origin = origin
	return base, err
}

func resolveOpenAPI3Base(spec map[string]any, documentURL, fallbackTarget string) (documentBase, error) {
	servers, _ := spec["servers"].([]any)
	if len(servers) == 0 {
		origin, err := documentOrigin(documentURL)
		return documentBase{origin: origin}, err
	}
	server, ok := servers[0].(map[string]any)
	if !ok {
		return documentBase{}, fmt.Errorf("first server entry is not an object")
	}
	serverURL, err := expandServerURL(server)
	if err != nil {
		return documentBase{}, fmt.Errorf("resolve server URL: %w", err)
	}
	resolved, err := resolveServerURL(serverURL, documentURL, fallbackTarget)
	if err != nil {
		return documentBase{}, err
	}
	origin, basePath, err := splitServerURL(resolved.String(), documentURL)
	if err != nil {
		return documentBase{}, err
	}
	return documentBase{origin: origin, basePath: basePath, namesBasePath: true}, nil
}

// swagger2BasePath returns a Swagger 2 document's normalized basePath and
// whether the document names one.
func swagger2BasePath(spec map[string]any) (string, bool) {
	basePath, ok := spec["basePath"].(string)
	if !ok {
		return "", false
	}
	return openapi.NormalizeBasePath(basePath), true
}

// documentOrigin is the origin of the document's own URL, the API target of
// a document that names no server.
func documentOrigin(documentURL string) (string, error) {
	if documentURL == "" {
		return "", errNoDocumentServer
	}
	origin, _, err := splitServerURL(documentURL, documentURL)
	return origin, err
}

// splitServerURL resolves raw as a server URL and splits it into its origin
// and its normalized base path.
func splitServerURL(raw, documentURL string) (string, string, error) {
	target, err := resolveServerURL(raw, documentURL, "")
	if err != nil {
		return "", "", err
	}
	basePath := openapi.NormalizeBasePath(target.EscapedPath())
	target.Path = ""
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	return target.String(), basePath, nil
}

// expandServerURL substitutes each server variable's default in one pass,
// left to right. A default is inserted as written and never expanded again,
// so a default that names a variable cannot make the expansion loop or grow.
func expandServerURL(server map[string]any) (string, error) {
	raw, _ := server["url"].(string)
	if raw == "" {
		return "", fmt.Errorf("server URL is empty")
	}
	variables, _ := server["variables"].(map[string]any)
	defaults := make(map[string]string)
	var expanded strings.Builder
	rest := raw
	for {
		start := strings.Index(rest, "{")
		if start < 0 {
			expanded.WriteString(rest)
			return expanded.String(), nil
		}
		endOffset := strings.Index(rest[start:], "}")
		if endOffset < 0 {
			return "", fmt.Errorf("unclosed server variable in %q", raw)
		}
		end := start + endOffset
		name := rest[start+1 : end]
		defaultValue, known := defaults[name]
		if !known {
			value, err := serverVariableDefault(variables, name)
			if err != nil {
				return "", err
			}
			defaults[name] = value
			defaultValue = value
		}
		expanded.WriteString(rest[:start])
		expanded.WriteString(defaultValue)
		rest = rest[end+1:]
	}
}

func serverVariableDefault(variables map[string]any, name string) (string, error) {
	definition, _ := variables[name].(map[string]any)
	defaultValue, ok := definition["default"].(string)
	if !ok {
		return "", fmt.Errorf("server variable %q has no string default", name)
	}
	if enum, exists := definition["enum"].([]any); exists && len(enum) > 0 {
		for _, candidate := range enum {
			if candidate == defaultValue {
				return defaultValue, nil
			}
		}
		return "", fmt.Errorf("server variable %q default is not listed in its enum", name)
	}
	return defaultValue, nil
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

func errorsUnsupportedVersion(version string) error {
	if version == "" {
		return fmt.Errorf("document does not declare a supported Swagger or OpenAPI version")
	}
	return fmt.Errorf("unsupported OpenAPI version %q; supported major versions are Swagger 2 and OpenAPI 3", version)
}
