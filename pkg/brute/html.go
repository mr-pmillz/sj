package brute

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxChallengeInspectionBytes      = 128 * 1024
	maxReferenceCandidatesPerPattern = 64
)

type referenceSet struct {
	URLs     []string
	Rejected int
	Skipped  int
}

type referencePattern struct {
	pattern    *regexp.Regexp
	permissive bool
}

var htmlReferencePatterns = []referencePattern{
	{pattern: regexp.MustCompile(`(?i)\burl\s*:\s*["']([^"']+)["']`)},
	{pattern: regexp.MustCompile(`(?i)\bconfigUrl\s*:\s*["']([^"']+)["']`), permissive: true},
	{pattern: regexp.MustCompile(`(?i)\bspecUrl\s*:\s*["']([^"']+)["']`), permissive: true},
}

var (
	htmlReferenceAttributePattern = regexp.MustCompile(`(?i)\b(spec-url|href|src)\s*=\s*["']([^"']+)["']`)
	swashbuckleDiscoveryPattern   = regexp.MustCompile(`(?i)discoveryPaths\s*:\s*arrayFrom\(\s*["']([^"']+)["']`)

	javascriptReferencePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\burl\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)\bconfigUrl\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)\bspecUrl\s*:\s*["']([^"']+)["']`),
	}
)

var swaggerUILibraryScripts = []string{
	"swagger-ui-bundle", "swagger-ui-standalone", "swagger-ui-es-bundle",
	"swagger-ui-layout", "swagger-ui-plugins", "swagger-ui.min", "swagger-ui.js",
	"redoc.standalone", "redoc.min", "redoc.js",
}

// ExtractSpecURLsFromHTML scans an HTML body for same-origin OpenAPI/Swagger
// references and initializer scripts. It is retained as the public extraction
// contract; the scanner also applies the same policy to JavaScript and JSON
// configuration responses.
func ExtractSpecURLsFromHTML(body []byte, baseURL string) []string {
	return extractHTMLReferences(body, baseURL).URLs
}

func extractDiscoveryReferences(body []byte, contentType, sourceURL string) referenceSet {
	lowerType := strings.ToLower(contentType)
	switch {
	case strings.Contains(lowerType, "javascript") || isJavaScriptURL(sourceURL):
		if isSwaggerUILibraryScript(sourceURL) {
			return referenceSet{}
		}
		return extractJavaScriptReferences(body, sourceURL)
	case strings.Contains(lowerType, "html") || looksLikeHTML(body) || looksLikeSwaggerUIPage(body):
		return extractHTMLReferences(body, sourceURL)
	case json.Valid(body):
		return extractSwaggerConfigReferences(body, sourceURL)
	default:
		return referenceSet{}
	}
}

func extractHTMLReferences(body []byte, baseURL string) referenceSet {
	collector := newReferenceCollector(baseURL)
	if collector == nil {
		return referenceSet{}
	}
	content := string(body)
	permissivePage := looksLikeSwaggerUIPage(body)
	for _, candidate := range htmlReferencePatterns {
		for _, match := range candidate.pattern.FindAllStringSubmatch(content, maxReferenceCandidatesPerPattern) {
			if len(match) < 2 || (!candidate.permissive && !permissivePage && !looksLikeSpecReference(match[1])) {
				continue
			}
			collector.add(match[1])
		}
	}
	for _, match := range htmlReferenceAttributePattern.FindAllStringSubmatch(content, maxReferenceCandidatesPerPattern) {
		if len(match) < 3 {
			continue
		}
		attribute, reference := strings.ToLower(match[1]), match[2]
		if isSwaggerUILibraryScript(reference) {
			continue
		}
		if attribute == "spec-url" || looksLikeSpecReference(reference) || looksLikeInitializerScript(reference) {
			collector.add(reference)
		}
	}
	if match := swashbuckleDiscoveryPattern.FindStringSubmatch(content); len(match) > 1 {
		for reference := range strings.SplitSeq(match[1], "|") {
			if collector.atInspectionLimit() {
				collector.skipped++
				break
			}
			reference = strings.TrimSpace(reference)
			if reference == "" {
				continue
			}
			if !strings.HasPrefix(reference, "/") && !strings.Contains(reference, "://") {
				reference = "/" + reference
			}
			collector.add(reference)
		}
	}
	return collector.result()
}

func extractJavaScriptReferences(body []byte, baseURL string) referenceSet {
	collector := newReferenceCollector(baseURL)
	if collector == nil {
		return referenceSet{}
	}
	content := string(body)
	for _, pattern := range javascriptReferencePatterns {
		for _, match := range pattern.FindAllStringSubmatch(content, maxReferenceCandidatesPerPattern) {
			if len(match) > 1 {
				collector.add(match[1])
			}
		}
	}
	return collector.result()
}

func extractSwaggerConfigReferences(body []byte, baseURL string) referenceSet {
	collector := newReferenceCollector(baseURL)
	if collector == nil {
		return referenceSet{}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return referenceSet{}
	}
	for _, key := range []string{"url", "configurl", "specurl", "urls"} {
		value, found := jsonField(document, key)
		if !found {
			continue
		}
		switch key {
		case "url", "configurl", "specurl":
			var reference string
			if json.Unmarshal(value, &reference) == nil {
				collector.add(reference)
			}
		case "urls":
			var entries []json.RawMessage
			if json.Unmarshal(value, &entries) != nil {
				continue
			}
			for _, entry := range entries {
				if collector.atInspectionLimit() {
					collector.skipped++
					break
				}
				var reference string
				if json.Unmarshal(entry, &reference) == nil {
					collector.add(reference)
					continue
				}
				var object map[string]json.RawMessage
				if json.Unmarshal(entry, &object) != nil {
					continue
				}
				for entryKey, entryValue := range object {
					if !strings.EqualFold(entryKey, "url") {
						continue
					}
					if json.Unmarshal(entryValue, &reference) == nil {
						collector.add(reference)
					}
				}
			}
		}
	}
	return collector.result()
}

func jsonField(document map[string]json.RawMessage, wanted string) (json.RawMessage, bool) {
	for key, value := range document {
		if strings.EqualFold(key, wanted) {
			return value, true
		}
	}
	return nil, false
}

type referenceCollector struct {
	base     *url.URL
	seen     map[string]struct{}
	urls     []string
	rejected int
	skipped  int
	examined int
}

func newReferenceCollector(baseURL string) *referenceCollector {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil
	}
	return &referenceCollector{base: base, seen: make(map[string]struct{})}
}

func (collector *referenceCollector) add(rawReference string) {
	rawReference = strings.TrimSpace(rawReference)
	if rawReference == "" {
		return
	}
	if collector.atInspectionLimit() {
		collector.skipped++
		return
	}
	collector.examined++
	reference, err := url.Parse(rawReference)
	if err != nil {
		collector.rejected++
		return
	}
	resolved := collector.base.ResolveReference(reference)
	if resolved.User != nil || (resolved.Scheme != "http" && resolved.Scheme != "https") || !sameOrigin(collector.base, resolved) {
		collector.rejected++
		return
	}
	resolved.Fragment = ""
	normalized := resolved.String()
	if _, found := collector.seen[normalized]; found {
		return
	}
	collector.seen[normalized] = struct{}{}
	if len(collector.urls) >= maxReferencesPerResponse {
		collector.skipped++
		return
	}
	collector.urls = append(collector.urls, normalized)
}

func (collector *referenceCollector) result() referenceSet {
	return referenceSet{URLs: collector.urls, Rejected: collector.rejected, Skipped: collector.skipped}
}

func (collector *referenceCollector) atInspectionLimit() bool {
	return collector.examined >= maxReferenceCandidatesPerPattern
}

func sameOrigin(first, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) && strings.EqualFold(first.Host, second.Host)
}

func looksLikeSwaggerUIPage(body []byte) bool {
	lower := bytes.ToLower(body[:min(len(body), maxChallengeInspectionBytes)])
	return bytes.Contains(lower, []byte("swaggeruibundle")) ||
		bytes.Contains(lower, []byte("swagger-ui")) ||
		bytes.Contains(lower, []byte("spec-url")) ||
		bytes.Contains(lower, []byte("discoverypaths")) ||
		bytes.Contains(lower, []byte("redoc"))
}

func looksLikeSpecReference(raw string) bool {
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	path := strings.ToLower(reference.Path)
	return strings.Contains(path, "openapi") || strings.Contains(path, "swagger") ||
		strings.Contains(path, "api-docs") || strings.Contains(path, "api_docs") ||
		strings.Contains(path, "apidocs") || strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") ||
		strings.HasSuffix(path, "-json") || strings.HasSuffix(path, "_json")
}

func looksLikeInitializerScript(raw string) bool {
	return isJavaScriptURL(raw) && !isSwaggerUILibraryScript(raw)
}

func isJavaScriptURL(raw string) bool {
	reference, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.HasSuffix(strings.ToLower(reference.Path), ".js")
}

func isSwaggerUILibraryScript(raw string) bool {
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	path := strings.ToLower(reference.Path)
	for _, library := range swaggerUILibraryScripts {
		if strings.Contains(path, library) {
			return true
		}
	}
	return false
}

func looksLikeWAFChallenge(body []byte, contentType string, status int) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body[:min(len(body), maxChallengeInspectionBytes)])
	htmlResponse := strings.Contains(strings.ToLower(contentType), "html") || looksLikeHTML(body)
	if !htmlResponse {
		return false
	}
	for _, marker := range [][]byte{
		[]byte("_cf_chl_opt"),
		[]byte("/cdn-cgi/challenge-platform"),
		[]byte("cf-browser-verification"),
		[]byte("attention required! | cloudflare"),
		[]byte("ddos protection by cloudflare"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	challengeStatus := status == 403 || status == 429 || status == 503
	if !challengeStatus {
		return false
	}
	return bytes.Contains(lower, []byte("just a moment...")) ||
		bytes.Contains(lower, []byte("enable javascript and cookies to continue")) ||
		bytes.Contains(lower, []byte("checking your browser before accessing"))
}
