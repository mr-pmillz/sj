package scanner

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
)

func GenerateRequests(bodyBytes []byte, client *httpclient.Client, cfg *config.Config, w *output.Writer, resolver *openapi.Resolver) {
	if openapi.LooksLikeJSSpec(bodyBytes, cfg.SwaggerURL, cfg.LocalFile, cfg.Format) {
		if extracted, ok := openapi.ExtractJSONFromJSSpec(bodyBytes); ok {
			bodyBytes = extracted
		}
	}

	spec := openapi.MustUnmarshalSpec(bodyBytes)

	openapi.CheckSecuritySchemes(spec, cfg, os.Stdin)

	u, parseErr := url.Parse(cfg.SwaggerURL)
	if parseErr != nil {
		u = &url.URL{}
	}

	if v, ok := spec["swagger"].(string); ok && strings.HasPrefix(v, "2") {
		host, _ := spec["host"].(string)
		bp, _ := spec["basePath"].(string)
		if bp != "" {
			cfg.BasePath = openapi.NormalizeBasePath(bp)
		}

		if cfg.APITarget == "" {
			if host != "" && strings.Contains(host, "://") {
				cfg.APITarget = host
			} else if host != "" {
				scheme := u.Scheme
				if scheme == "" {
					if schemes, ok := spec["schemes"].([]any); ok && len(schemes) > 0 {
						if s, ok := schemes[0].(string); ok {
							scheme = s
						}
					}
				}
				if scheme == "" {
					scheme = "https"
				}
				cfg.APITarget = scheme + "://" + host
			}
		}
	} else if v, ok := spec["openapi"].(string); ok && strings.HasPrefix(v, "3") {
		if servers, ok := spec["servers"].([]any); ok && len(servers) > 0 {
			if len(servers) > 1 {
				if !cfg.Quiet && cfg.Mode != config.ModeEndpoints && cfg.APITarget == "" {
					output.PrintWarn("Multiple servers detected in documentation. You can manually set a server to test with the -T flag.\nThe detected servers are as follows:")
					for i := range servers {
						if srv, ok := servers[i].(map[string]any); ok {
							if serverURL, ok := srv["url"].(string); ok {
								if strings.Contains(serverURL, "://") {
									fmt.Println(serverURL)
								} else {
									fmt.Println(cfg.APITarget + serverURL)
								}
							}
						}
					}
				}
			} else {
				if srv, ok := servers[0].(map[string]any); ok {
					if serverURL, ok := srv["url"].(string); ok {
						if strings.Contains(serverURL, "://") {
							if parsedServerURL, err := url.Parse(serverURL); err == nil {
								cfg.BasePath = openapi.NormalizeBasePath(parsedServerURL.Path)
								if cfg.APITarget == "" {
									cfg.APITarget = parsedServerURL.Scheme + "://" + parsedServerURL.Host
								}
							}
						} else if serverURL == "/" {
							cfg.BasePath = ""
						} else {
							cfg.BasePath = openapi.NormalizeBasePath(serverURL)
							if cfg.APITarget == "" {
								if u.Scheme != "" && u.Host != "" {
									cfg.APITarget = u.Scheme + "://" + u.Host
								} else if cfg.Mode != config.ModeEndpoints {
									output.Die("Spec has relative server URL '%s' but no base URL available. Use -T to specify target server.", serverURL)
								}
							}
						}
					}
				}
			}
		}
	}

	if cfg.APITarget == "" {
		if u.Scheme != "" && u.Host != "" {
			cfg.APITarget = u.Scheme + "://" + u.Host
		} else if cfg.Mode != config.ModeEndpoints {
			output.Die("No server information found in spec and no URL provided. Use -T to specify target server.")
		}
	}

	if cfg.Mode != config.ModeEndpoints {
		openapi.PrintSpecInfo(spec, w, cfg)
	}

	BuildRequestsFromPaths(spec, client, cfg, w, resolver)
}
