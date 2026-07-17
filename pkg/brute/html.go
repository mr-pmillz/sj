package brute

import (
	"net/url"
	"regexp"
	"strings"
)

// htmlSpecURLPatterns matches common patterns in HTML pages that reference
// OpenAPI/Swagger specification URLs.
var htmlSpecURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)url\s*:\s*["']((?:/|https?://)[^"']*(?:\.json|\.yaml|\.yml|/api-docs|/swagger|/openapi|/v[0-9]+/api)[^"']*)["']`),
	regexp.MustCompile(`(?i)spec-url\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)configUrl\s*:\s*["']([^"']+)["']`),
}

// ExtractSpecURLsFromHTML scans an HTML body for embedded references to
// specification files and returns absolute URLs.
func ExtractSpecURLsFromHTML(body []byte, baseURL string) []string {
	var urls []string
	seen := map[string]bool{}

	for _, re := range htmlSpecURLPatterns {
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			if len(m) < 2 {
				continue
			}
			specURL := m[1]

			if strings.HasPrefix(specURL, "//") {
				if u, err := url.Parse(baseURL); err == nil {
					specURL = u.Scheme + ":" + specURL
				}
			} else if strings.HasPrefix(specURL, "/") {
				if u, err := url.Parse(baseURL); err == nil {
					specURL = u.Scheme + "://" + u.Host + specURL
				}
			} else if !strings.HasPrefix(specURL, "http") {
				specURL = strings.TrimRight(baseURL, "/") + "/" + specURL
			}

			if !seen[specURL] {
				seen[specURL] = true
				urls = append(urls, specURL)
			}
		}
	}
	return urls
}
