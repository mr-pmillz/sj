package brute

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"gopkg.in/yaml.v3"
)

// Scanner drives the brute-force search for OpenAPI specification files.
type Scanner struct {
	Client *httpclient.Client
	Cfg    *config.Config
}

// NewScanner returns a Scanner wired to the given HTTP client and config.
func NewScanner(client *httpclient.Client, cfg *config.Config) *Scanner {
	return &Scanner{Client: client, Cfg: cfg}
}

// RunTarget brute-forces a single target URL looking for spec files.
// When dumpSpec is true the first discovered spec body is written to
// the configured outfile or stdout.
func (s *Scanner) RunTarget(targetURL string, dumpSpec bool) Report {
	u, err := url.Parse(targetURL)
	if err != nil {
		output.PrintWarn("Error parsing URL: %s", err)
		return Report{Target: targetURL}
	}
	target := u.Scheme + "://" + u.Host
	normalizedBasePath := openapi.NormalizeBasePath(s.Cfg.BasePath)

	var allURLs []string
	if s.Cfg.EndpointWordlist == "" {
		allURLs = append(allURLs, MakeURLs(target, normalizedBasePath, PriorityURLs, "", true)...)
		allURLs = append(allURLs, MakeURLs(target, normalizedBasePath, JSONEndpoints, "", false)...)
		allURLs = append(allURLs, MakeURLs(target, normalizedBasePath, JavaScriptEndpoints, ".js", false)...)
		allURLs = append(allURLs, MakeURLs(target, normalizedBasePath, JSONEndpoints, ".json", false)...)
		allURLs = append(allURLs, MakeURLs(target, normalizedBasePath, JSONEndpoints, "/", false)...)
	} else {
		file, fileErr := os.Open(s.Cfg.EndpointWordlist)
		if fileErr != nil {
			output.Die("Failed to open file: %s", fileErr)
		}
		defer file.Close()
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			endpoint := sc.Text()
			allURLs = append(allURLs, target+normalizedBasePath+endpoint)
		}
	}

	output.PrintInfo("Sending %d requests. This could take a while...\n", len(allURLs))

	matches, interesting, summary := s.findAllDefinitionFiles(allURLs)

	report := Report{
		Target:      targetURL,
		Interesting: interesting,
		Summary:     summary,
	}
	for _, m := range matches {
		report.SpecsFound = append(report.SpecsFound, SpecResult{
			URL:            m.url,
			ContentType:    m.contentType,
			OpenAPIVersion: m.version,
			Title:          m.title,
			Description:    m.description,
		})
	}
	report.Summary.SpecsFoundCount = len(matches)

	if strings.EqualFold(s.Cfg.BruteOutputFormat, "json") {
		return report
	}

	if len(matches) > 0 {
		fmt.Fprintln(os.Stderr)
		for i, m := range matches {
			output.PrintInfo("Definition file found: %s\n", m.url)
			if s.Cfg.EndpointOnly {
				continue
			}
			if dumpSpec && i == 0 {
				definedOperations, marshalErr := json.Marshal(m.spec)
				if marshalErr != nil {
					output.PrintErr("Error parsing definition file: %s", marshalErr)
					continue
				}
				if s.Cfg.Outfile != "" {
					writeErr := os.WriteFile(s.Cfg.Outfile, definedOperations, 0644)
					if writeErr != nil {
						output.PrintErr("Error writing file: %s", writeErr)
					} else {
						f, _ := filepath.Abs(s.Cfg.Outfile)
						output.PrintInfo("Wrote file to %s\n", f)
					}
				} else {
					fmt.Println(string(definedOperations))
				}
			}
		}

		if len(matches) > 1 {
			output.PrintInfo("\nFound %d definition files total:\n", len(matches))
			for _, m := range matches {
				line := fmt.Sprintf("  - %s (OpenAPI %s", m.url, m.version)
				if m.title != "" {
					line += ", " + m.title
				}
				line += ")"
				output.PrintInfo("%s\n", line)
			}
		}
	} else {
		output.PrintErr("\nNo definition file found for:\t%s", targetURL)
	}

	if len(interesting) > 0 {
		output.PrintInfo("\nInteresting URLs found:\n")
		for _, iu := range interesting {
			output.PrintInfo("  [%d] %s (%s)\n", iu.StatusCode, iu.URL, iu.ContentType)
		}
	}

	output.PrintInfo("\nSummary: %d URLs tested, %d specs found, %d interesting, %d errors\n",
		summary.URLsTested, len(matches), len(interesting), summary.Errors)

	return report
}

// findAllDefinitionFiles iterates over candidate URLs, fetches each one, and
// attempts to parse the response as an OpenAPI spec. HTML pages are scanned
// for embedded spec-URL references, which are then also fetched.
func (s *Scanner) findAllDefinitionFiles(urls []string) ([]match, []Interesting, Summary) {
	var matches []match
	var interesting []Interesting
	var summary Summary

	tested := make(map[string]bool, len(urls))
	for _, u := range urls {
		tested[u] = true
	}

	foundURLs := make(map[string]bool)
	var extraURLs []string

	processURL := func(targetURL string, index, total int) {
		summary.URLsTested++

		bodyBytes, ct, statusCode := s.Client.BruteFetch(targetURL)

		if index == total-1 {
			fmt.Fprintf(os.Stderr, "\033[2K\r%s%d\n", "Request: ", index+1)
		} else {
			fmt.Fprintf(os.Stderr, "\033[2K\r%s%d", "Request: ", index+1)
		}

		if statusCode == 0 {
			summary.Errors++
			return
		}

		switch {
		case statusCode >= 200 && statusCode < 300:
			summary.Responses2xx++
		case statusCode >= 300 && statusCode < 400:
			summary.Responses3xx++
		case statusCode >= 400 && statusCode < 500:
			summary.Responses4xx++
		default:
			summary.Errors++
		}

		if len(bodyBytes) == 0 || statusCode != 200 {
			return
		}

		ctLower := strings.ToLower(ct)

		if strings.Contains(ctLower, "application/json") || isYAMLContentType(ctLower) {
			if spec, version := TryParseAsSpec(bodyBytes); spec != nil {
				if !foundURLs[targetURL] {
					foundURLs[targetURL] = true
					m := match{url: targetURL, contentType: ct, spec: spec, version: version}
					if spec.Info != nil {
						m.title = spec.Info.Title
						m.description = spec.Info.Description
					}
					matches = append(matches, m)
				}
			}
			return
		}

		if strings.Contains(ctLower, "application/javascript") || strings.Contains(ctLower, "text/javascript") {
			if jsonContent, ok := openapi.ExtractJSONFromJSSpec(bodyBytes); ok {
				if spec, version := TryParseAsSpec(jsonContent); spec != nil {
					m := match{url: targetURL, contentType: ct, spec: spec, version: version}
					if spec.Info != nil {
						m.title = spec.Info.Title
						m.description = spec.Info.Description
					}
					matches = append(matches, m)
				}
			}
			return
		}

		if strings.Contains(ctLower, "text/html") {
			specURLs := ExtractSpecURLsFromHTML(bodyBytes, targetURL)
			for _, su := range specURLs {
				if !tested[su] {
					tested[su] = true
					extraURLs = append(extraURLs, su)
				}
			}
			if len(specURLs) > 0 {
				interesting = append(interesting, Interesting{
					URL: targetURL, StatusCode: statusCode, ContentType: ct,
				})
			}
			return
		}

		urlLower := strings.ToLower(targetURL)
		if strings.HasSuffix(urlLower, ".json") || strings.HasSuffix(urlLower, ".yaml") || strings.HasSuffix(urlLower, ".yml") {
			if spec, version := TryParseAsSpec(bodyBytes); spec != nil {
				if !foundURLs[targetURL] {
					foundURLs[targetURL] = true
					m := match{url: targetURL, contentType: ct, spec: spec, version: version}
					if spec.Info != nil {
						m.title = spec.Info.Title
						m.description = spec.Info.Description
					}
					matches = append(matches, m)
				}
			}
		}
	}

	for i, u := range urls {
		processURL(u, i, len(urls))
	}

	if len(extraURLs) > 0 {
		output.PrintInfo("\nDiscovered %d additional spec URLs from HTML pages. Testing...\n", len(extraURLs))
		for i, u := range extraURLs {
			processURL(u, i, len(extraURLs))
		}
	}

	return matches, interesting, summary
}

// TryParseAsSpec attempts to parse raw bytes as an OpenAPI 3.x or Swagger 2.0
// spec (JSON or YAML). Returns the parsed spec and its version string, or nil
// if parsing fails.
func TryParseAsSpec(bodyBytes []byte) (*openapi3.T, string) {
	var doc3 openapi3.T
	_ = json.Unmarshal(bodyBytes, &doc3)
	if strings.HasPrefix(doc3.OpenAPI, "3") && doc3.Paths != nil {
		return &doc3, doc3.OpenAPI
	}

	var doc2 openapi2.T
	_ = json.Unmarshal(bodyBytes, &doc2)
	if strings.HasPrefix(doc2.Swagger, "2") {
		converted, convErr := openapi2conv.ToV3(&doc2)
		if convErr == nil && converted != nil && converted.Paths != nil {
			return converted, "2.0"
		}
	}

	doc3 = openapi3.T{}
	_ = yaml.Unmarshal(bodyBytes, &doc3)
	if strings.HasPrefix(doc3.OpenAPI, "3") && doc3.Paths != nil {
		return &doc3, doc3.OpenAPI
	}

	doc2 = openapi2.T{}
	_ = yaml.Unmarshal(bodyBytes, &doc2)
	if strings.HasPrefix(doc2.Swagger, "2") {
		converted, convErr := openapi2conv.ToV3(&doc2)
		if convErr == nil && converted != nil && converted.Paths != nil {
			return converted, "2.0"
		}
	}

	return nil, ""
}

// isYAMLContentType returns true when ct looks like a YAML media type.
func isYAMLContentType(ct string) bool {
	return strings.Contains(ct, "application/yaml") ||
		strings.Contains(ct, "application/x-yaml") ||
		strings.Contains(ct, "text/yaml") ||
		strings.Contains(ct, "text/x-yaml") ||
		strings.Contains(ct, "text/vnd.yaml")
}
