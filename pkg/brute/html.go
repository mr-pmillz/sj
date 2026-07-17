package brute

import (
	"net/url"
	"regexp"
	"strings"
)

// htmlSpecURLPatterns matches common patterns in HTML pages that reference
// OpenAPI/Swagger specification URLs.
var htmlSpecURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\burl\s*:\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)spec-url\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)configUrl\s*:\s*["']([^"']+)["']`),
}

// ExtractSpecURLsFromHTML scans an HTML body for embedded references to
// specification files and returns absolute URLs.
func ExtractSpecURLsFromHTML(body []byte, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil
	}
	var urls []string
	seen := map[string]bool{}

	for _, re := range htmlSpecURLPatterns {
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			if len(m) < 2 {
				continue
			}
			reference, parseErr := url.Parse(strings.TrimSpace(m[1]))
			if parseErr != nil {
				continue
			}
			resolved := base.ResolveReference(reference)
			if resolved.Scheme != "http" && resolved.Scheme != "https" {
				continue
			}
			if !sameOrigin(base, resolved) || resolved.User != nil {
				continue
			}
			resolved.Fragment = ""
			specURL := resolved.String()
			if !seen[specURL] {
				seen[specURL] = true
				urls = append(urls, specURL)
			}
		}
	}
	return urls
}

func sameOrigin(first, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) && strings.EqualFold(first.Host, second.Host)
}
