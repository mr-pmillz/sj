package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// --- Structured output types ---

type BruteSpecResult struct {
	URL            string `json:"url"`
	ContentType    string `json:"content_type"`
	OpenAPIVersion string `json:"openapi_version"`
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
}

type BruteInteresting struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
}

type BruteReport struct {
	Target      string             `json:"target"`
	SpecsFound  []BruteSpecResult  `json:"specs_found"`
	Interesting []BruteInteresting `json:"interesting_urls,omitempty"`
	Summary     BruteSummary       `json:"summary"`
}

type BruteSummary struct {
	URLsTested      int `json:"urls_tested"`
	SpecsFoundCount int `json:"specs_found_count"`
	Responses2xx    int `json:"responses_2xx"`
	Responses3xx    int `json:"responses_3xx"`
	Responses4xx    int `json:"responses_4xx"`
	Errors          int `json:"errors"`
}

type bruteMatch struct {
	url         string
	contentType string
	spec        *openapi3.T
	version     string
	title       string
	description string
}

// --- Flags ---

var endpointOnly bool
var endpointWordlist string
var bruteOutputFormat string
var bruteURLFile string

// --- Wordlists ---

var prefixDirs = []string{"", "/swagger", "/swagger/docs", "/swagger/latest", "/swagger/v1", "/swagger/v2", "/swagger/v3", "/swagger/static", "/swagger/ui", "/swagger-ui", "/api-docs", "/api-docs/v1", "/api-docs/v2", "/apidocs", "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3", "/doc", "/docs", "/docs/swagger", "/docs/swagger/v1", "/docs/swagger/v2", "/docs/swagger-ui", "/docs/swagger-ui/v1", "/docs/swagger-ui/v2", "/docs/v1", "/docs/v2", "/docs/v3", "/public", "/redoc"}
var jsonEndpoints = []string{"", "/index", "/swagger", "/swagger-ui", "/swagger-resources", "/swagger-config", "/openapi", "/api", "/api-docs", "/apidocs", "/v1", "/v2", "/v3", "/doc", "/docs", "/apispec", "/apispec_1", "/api-merged"}
var javascriptEndpoints = []string{"/swagger-ui-init", "/swagger-ui-bundle", "/swagger-ui-standalone-preset", "/swagger-ui", "/swagger-ui.min", "/swagger-ui-es-bundle-core", "/swagger-ui-es-bundle", "/swagger-ui-standalone-preset", "/swagger-ui-layout", "/swagger-ui-plugins"}
var priorityURLs = []string{"/swagger.json", "/openapi.json", "/api-docs", "/swagger", "/docs", "/api/swagger.json", "/api/openapi.json", "/api-docs/swagger.json", "/api/schema/", "/webjars/swagger-ui/index.html", "/API/swagger/ui/index", "/swagger/ui/index", "/v2/swagger.json", "/v2/openapi.json", "/v2/api-docs", "/v3/api-docs", "/v3/openapi.json", "/public/api-merged.json", "/analytics/v1/swagger", "/api.json", "/api/4.0/swagger.json", "/api/api-doc/openapi.json", "/api/api-doc/openapi.yaml", "/api/doc.json", "/api/docs.json", "/api/swagger", "/api/swagger/ui/index", "/api/v1/swagger", "/api/v2/api-docs", "/api/v2/openapi.json", "/api/v2/swagger.json", "/api/v3/api-docs", "/api/v3/apispec", "/api/workorder/openapi.json", "/apidocs", "/audiences/v1/swagger", "/audittrail/v1/swagger", "/certification/v1/swagger", "/citrixapi/store/swagger.json", "/conferencetool/v1/swagger", "/course/v1/swagger", "/dcl_swagger.yaml", "/doc/doc.json", "/doc/swagger.json", "/docs/swagger.json", "/docs/v1/swagger.json", "/ecommerce/v1/swagger", "/enrollment/v1/swagger", "/externalids/v1/swagger", "/impact/v1/swagger", "/learn/v1/swagger", "/learningplan/v1/swagger", "/manage/v1/swagger", "/management/info", "/marketplace/v1/swagger", "/messenger/v1/swagger", "/notifications/v1/swagger", "/openapi", "/openapi/spec.json", "/otj/v1/swagger", "/pages/v1/swagger", "/poweruser/v1/swagger", "/proctoring/v1/swagger", "/report/v1/swagger", "/swagger-ui/index.html", "/swagger-ui/openapi.json", "/swagger.yaml", "/swagger/0.1.0/swagger.json", "/swagger/doc.json", "/swagger/latest/swagger.json", "/swagger/swagger.json", "/swagger/test/swagger.json", "/swagger/ui/index.html", "/swagger/v1/openapiv2.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/swagger/v4/swagger.json", "/v1/openapi.json", "/v1/swagger", "/v1/swagger.json", "/swagger/docs/v1", "/swagger/docs/v1.json", "/Api/swagger/docs/v1", "/swagger/v1/swagger.json", "/api/api-docs/swagger.json", "/api/docs/", "/api/docs", "/swagger-ui"}

// --- Command ---

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Sends a series of automated requests to discover hidden API operation definitions.",
	Long:  `The brute command sends requests to the target to find operation definitions based on commonly used file locations.`,
	Run: func(cmd *cobra.Command, args []string) {
		if randomUserAgent {
			if UserAgent != "Swagger Jacker (github.com/BishopFox/sj)" {
				printWarn("A supplied User Agent was detected (%s) while supplying the 'random-user-agent' flag.", UserAgent)
			}
		}

		client, _ := CheckAndConfigureProxy()

		var targets []string
		if bruteURLFile != "" {
			file, err := os.Open(bruteURLFile)
			if err != nil {
				die("Failed to open URL file: %s", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
			if err := scanner.Err(); err != nil {
				die("Failed to read URL file: %s", err)
			}
			if len(targets) == 0 {
				die("No URLs found in file: %s", bruteURLFile)
			}
		} else if swaggerURL != "" {
			targets = append(targets, swaggerURL)
		} else {
			die("No target specified. Use -u for a single URL or -U for a file of URLs.")
		}

		var allReports []BruteReport
		isBatch := len(targets) > 1

		for i, targetURL := range targets {
			if isBatch {
				printInfo("\n[%d/%d] Brute-forcing: %s\n", i+1, len(targets), targetURL)
			}

			swaggerURL = targetURL
			report := bruteTarget(targetURL, client, !isBatch)
			allReports = append(allReports, report)
		}

		if strings.ToLower(bruteOutputFormat) == "json" {
			outputBruteJSON(allReports)
		} else if isBatch {
			printBruteBatchSummary(allReports)
		}
	},
}

// bruteTarget runs the brute-force scan against a single target URL.
// When dumpSpec is true, the first found spec definition is written to
// stdout or the -o file (backward-compatible single-target behavior).
func bruteTarget(targetURL string, client http.Client, dumpSpec bool) BruteReport {
	u, err := url.Parse(targetURL)
	if err != nil {
		printWarn("Error parsing URL: %s", err)
		return BruteReport{Target: targetURL}
	}
	target := u.Scheme + "://" + u.Host
	normalizedBasePath := normalizeBasePath(basePath)

	var allURLs []string
	if endpointWordlist == "" {
		allURLs = append(allURLs, makeURLs(target, normalizedBasePath, priorityURLs, "", true)...)
		allURLs = append(allURLs, makeURLs(target, normalizedBasePath, jsonEndpoints, "", false)...)
		allURLs = append(allURLs, makeURLs(target, normalizedBasePath, javascriptEndpoints, ".js", false)...)
		allURLs = append(allURLs, makeURLs(target, normalizedBasePath, jsonEndpoints, ".json", false)...)
		allURLs = append(allURLs, makeURLs(target, normalizedBasePath, jsonEndpoints, "/", false)...)
	} else {
		endpointList, err := os.Open(endpointWordlist)
		if err != nil {
			die("Failed to open file: %s", err)
		}
		defer endpointList.Close()
		scanner := bufio.NewScanner(endpointList)
		for scanner.Scan() {
			endpoint := scanner.Text()
			allURLs = append(allURLs, target+normalizedBasePath+endpoint)
		}
		if err := scanner.Err(); err != nil {
			die("Failed to read words from file: %s", err)
		}
	}

	printInfo("Sending %d requests. This could take a while...\n", len(allURLs))

	matches, interesting, summary := findAllDefinitionFiles(allURLs, client)

	report := BruteReport{
		Target:      targetURL,
		Interesting: interesting,
		Summary:     summary,
	}
	for _, m := range matches {
		report.SpecsFound = append(report.SpecsFound, BruteSpecResult{
			URL:            m.url,
			ContentType:    m.contentType,
			OpenAPIVersion: m.version,
			Title:          m.title,
			Description:    m.description,
		})
	}
	report.Summary.SpecsFoundCount = len(matches)

	if strings.ToLower(bruteOutputFormat) == "json" {
		return report
	}

	// Console output
	if len(matches) > 0 {
		fmt.Fprintln(os.Stderr)
		for i, m := range matches {
			printInfo("Definition file found: %s\n", m.url)

			if endpointOnly {
				continue
			}

			if dumpSpec && i == 0 {
				definedOperations, err := json.Marshal(m.spec)
				if err != nil {
					printErr("Error parsing definition file: %s", err)
					continue
				}
				if outfile != "" {
					writeErr := os.WriteFile(outfile, definedOperations, 0644)
					if writeErr != nil {
						printErr("Error writing file: %s", writeErr)
					} else {
						f, _ := filepath.Abs(outfile)
						printInfo("Wrote file to %s\n", f)
					}
				} else {
					fmt.Println(string(definedOperations))
				}
			}
		}

		if len(matches) > 1 {
			printInfo("\nFound %d definition files total:\n", len(matches))
			for _, m := range matches {
				line := fmt.Sprintf("  - %s (OpenAPI %s", m.url, m.version)
				if m.title != "" {
					line += ", " + m.title
				}
				line += ")"
				printInfo("%s\n", line)
			}
		}
	} else {
		printErr("\nNo definition file found for:\t%s", targetURL)
	}

	if len(interesting) > 0 {
		printInfo("\nInteresting URLs found:\n")
		for _, iu := range interesting {
			printInfo("  [%d] %s (%s)\n", iu.StatusCode, iu.URL, iu.ContentType)
		}
	}

	printInfo("\nSummary: %d URLs tested, %d specs found, %d interesting, %d errors\n",
		summary.URLsTested, len(matches), len(interesting), summary.Errors)

	return report
}

// findAllDefinitionFiles scans all candidate URLs using a single GET per URL
// and returns every valid spec found, plus interesting non-spec URLs.
func findAllDefinitionFiles(urls []string, client http.Client) ([]bruteMatch, []BruteInteresting, BruteSummary) {
	var matches []bruteMatch
	var interesting []BruteInteresting
	var summary BruteSummary

	tested := make(map[string]bool, len(urls))
	for _, u := range urls {
		tested[u] = true
	}

	foundURLs := make(map[string]bool)
	var extraURLs []string

	processURL := func(targetURL string, index, total int) {
		summary.URLsTested++

		bodyBytes, ct, statusCode := bruteFetch(client, targetURL)

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
			if spec, version := tryParseAsSpec(bodyBytes); spec != nil {
				if !foundURLs[targetURL] {
					foundURLs[targetURL] = true
					m := bruteMatch{url: targetURL, contentType: ct, spec: spec, version: version}
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
			if jsonContent, ok := ExtractJSONFromJSSpec(bodyBytes); ok {
				if spec, version := tryParseAsSpec(jsonContent); spec != nil {
					m := bruteMatch{url: targetURL, contentType: ct, spec: spec, version: version}
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
			specURLs := extractSpecURLsFromHTML(bodyBytes, targetURL)
			for _, su := range specURLs {
				if !tested[su] {
					tested[su] = true
					extraURLs = append(extraURLs, su)
				}
			}
			if len(specURLs) > 0 {
				interesting = append(interesting, BruteInteresting{
					URL: targetURL, StatusCode: statusCode, ContentType: ct,
				})
			}
			return
		}

		// Servers sometimes return text/plain for .json/.yaml files
		urlLower := strings.ToLower(targetURL)
		if strings.HasSuffix(urlLower, ".json") || strings.HasSuffix(urlLower, ".yaml") || strings.HasSuffix(urlLower, ".yml") {
			if spec, version := tryParseAsSpec(bodyBytes); spec != nil {
				if !foundURLs[targetURL] {
					foundURLs[targetURL] = true
					m := bruteMatch{url: targetURL, contentType: ct, spec: spec, version: version}
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
		printInfo("\nDiscovered %d additional spec URLs from HTML pages. Testing...\n", len(extraURLs))
		for i, u := range extraURLs {
			processURL(u, i, len(extraURLs))
		}
	}

	return matches, interesting, summary
}

// bruteFetch makes a single GET request and returns the body, content-type,
// and status code. This replaces the old pattern of separate HEAD + GET.
func bruteFetch(client http.Client, target string) ([]byte, string, int) {
	u, err := url.Parse(target)
	if err != nil || u == nil {
		return nil, "", 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, "", 0
	}

	for i := range Headers {
		delimIndex := strings.Index(Headers[i], ":")
		if delimIndex == -1 {
			continue
		}
		key := strings.TrimSpace(Headers[i][:delimIndex])
		value := strings.TrimSpace(Headers[i][delimIndex+1:])
		req.Header.Set(key, value)
	}

	if randomUserAgent {
		UserAgent = userAgents[rand.Intn(len(userAgents))]
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json, application/yaml, text/html, */*")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, "", 0
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, resp.Header.Get("Content-Type"), resp.StatusCode
	}

	return bodyBytes, resp.Header.Get("Content-Type"), resp.StatusCode
}

// tryParseAsSpec attempts to parse bytes as an OpenAPI/Swagger spec using
// both JSON and YAML deserialisation. Returns the parsed spec and a version
// string, or (nil, "") when the bytes are not a valid spec.
func tryParseAsSpec(bodyBytes []byte) (*openapi3.T, string) {
	// Try JSON as OpenAPI 3
	var doc3 openapi3.T
	_ = json.Unmarshal(bodyBytes, &doc3)
	if strings.HasPrefix(doc3.OpenAPI, "3") && doc3.Paths != nil {
		return &doc3, doc3.OpenAPI
	}

	// Try JSON as Swagger 2 and convert
	var doc2 openapi2.T
	_ = json.Unmarshal(bodyBytes, &doc2)
	if strings.HasPrefix(doc2.Swagger, "2") {
		converted, err := openapi2conv.ToV3(&doc2)
		if err == nil && converted != nil && converted.Paths != nil {
			return converted, "2.0"
		}
	}

	// Try YAML as OpenAPI 3
	doc3 = openapi3.T{}
	_ = yaml.Unmarshal(bodyBytes, &doc3)
	if strings.HasPrefix(doc3.OpenAPI, "3") && doc3.Paths != nil {
		return &doc3, doc3.OpenAPI
	}

	// Try YAML as Swagger 2 and convert
	doc2 = openapi2.T{}
	_ = yaml.Unmarshal(bodyBytes, &doc2)
	if strings.HasPrefix(doc2.Swagger, "2") {
		converted, err := openapi2conv.ToV3(&doc2)
		if err == nil && converted != nil && converted.Paths != nil {
			return converted, "2.0"
		}
	}

	return nil, ""
}

func isYAMLContentType(ct string) bool {
	return strings.Contains(ct, "application/yaml") ||
		strings.Contains(ct, "application/x-yaml") ||
		strings.Contains(ct, "text/yaml") ||
		strings.Contains(ct, "text/x-yaml") ||
		strings.Contains(ct, "text/vnd.yaml")
}

var htmlSpecURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)url\s*:\s*["']((?:/|https?://)[^"']*(?:\.json|\.yaml|\.yml|/api-docs|/swagger|/openapi|/v[0-9]+/api)[^"']*)["']`),
	regexp.MustCompile(`(?i)spec-url\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)configUrl\s*:\s*["']([^"']+)["']`),
}

func extractSpecURLsFromHTML(body []byte, baseURL string) []string {
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

func outputBruteJSON(reports []BruteReport) {
	var output any
	if len(reports) == 1 {
		output = reports[0]
	} else {
		output = reports
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		printErr("Error marshalling JSON: %s", err)
		return
	}

	if outfile != "" {
		writeErr := os.WriteFile(outfile, data, 0644)
		if writeErr != nil {
			printErr("Error writing file: %s", writeErr)
		} else {
			f, _ := filepath.Abs(outfile)
			printInfo("Wrote report to %s\n", f)
		}
	} else {
		fmt.Println(string(data))
	}
}

func printBruteBatchSummary(reports []BruteReport) {
	totalSpecs := 0
	totalTested := 0
	totalErrors := 0
	targetsWithSpecs := 0
	for _, r := range reports {
		totalSpecs += r.Summary.SpecsFoundCount
		totalTested += r.Summary.URLsTested
		totalErrors += r.Summary.Errors
		if r.Summary.SpecsFoundCount > 0 {
			targetsWithSpecs++
		}
	}
	printInfo("\n=== Batch Summary ===\n")
	printInfo("Targets processed:  %d\n", len(reports))
	printInfo("Targets with specs: %d\n", targetsWithSpecs)
	printInfo("Total URLs tested:  %d\n", totalTested)
	printInfo("Total specs found:  %d\n", totalSpecs)
	printInfo("Total errors:       %d\n", totalErrors)
}

// --- Kept functions (unchanged) ---

func makeURLs(target string, basePath string, endpoints []string, fileExtension string, skipPrefix bool) []string {
	urls := []string{}
	if !skipPrefix {
		for _, dir := range prefixDirs {
			for _, endpoint := range endpoints {
				if dir == "" && endpoint == "" {
					continue
				}
				targetURL := target + basePath + dir + endpoint + fileExtension
				urls = append(urls, targetURL)
			}
		}
	} else {
		for _, endpoint := range endpoints {
			if endpoint == "" {
				continue
			}
			targetURL := target + basePath + endpoint + fileExtension
			urls = append(urls, targetURL)
		}
	}
	return urls
}

// ExtractJSONFromJSSpec scans a Swagger-UI-style JavaScript bundle for an
// OpenAPI/Swagger document assigned to a top-level var/let/const. If the
// captured value is itself a wrapper object (swagger-ui-express / swagger-ui
// bundle config), it unwraps one level via the swaggerDoc/spec/openapi keys.
// Returns the extracted JSON bytes and true on success, or the original
// bytes and false on failure.
func ExtractJSONFromJSSpec(bodyBytes []byte) ([]byte, bool) {
	re := regexp.MustCompile(`(?s)(?:let|const|var)\s+(\w+)\s*=\s*({.*?});`)
	matches := re.FindAllStringSubmatch(string(bodyBytes), -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		candidate := []byte(m[2])
		if looksLikeAPISpec(candidate) {
			return candidate, true
		}
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(candidate, &wrapper); err != nil {
			continue
		}
		for _, key := range []string{"swaggerDoc", "spec", "openapi"} {
			if inner, ok := wrapper[key]; ok && looksLikeAPISpec(inner) {
				return inner, true
			}
		}
	}
	return bodyBytes, false
}

func looksLikeAPISpec(b []byte) bool {
	var probe struct {
		OpenAPI string `json:"openapi"`
		Swagger string `json:"swagger"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(probe.OpenAPI, "3") ||
		strings.HasPrefix(probe.OpenAPI, "2") ||
		strings.HasPrefix(probe.Swagger, "2")
}

func ExtractSpecFromJS(bodyBytes []byte) []byte {
	var openApiIndex int
	var specClose int
	var bodyString, spec string

	bodyString = string(bodyBytes)
	spec = strings.ReplaceAll(bodyString, "\n", "")
	spec = strings.ReplaceAll(spec, "\t", "")
	spec = strings.ReplaceAll(spec, " ", "")

	if strings.Contains(strings.ReplaceAll(bodyString, " ", ""), `"swagger":"2.0"`) {
		openApiIndex = strings.Index(spec, `"swagger":`) - 1
		specClose = strings.LastIndex(spec, "]}") + 2

		var doc2 openapi2.T
		bodyBytes = []byte(spec[openApiIndex:specClose])
		_ = json.Unmarshal(bodyBytes, &doc2)
		if !strings.Contains(doc2.Swagger, "2") {
			specClose = strings.LastIndex(spec, "}") + 1
			bodyBytes = []byte(spec[openApiIndex:specClose])
			_ = json.Unmarshal(bodyBytes, &doc2)
			if !strings.Contains(doc2.Swagger, "2") {
				printErr("Error parsing JavaScript file for spec. Try saving the object as a JSON file and reference it locally.")
			}
		}
	} else if strings.Contains(strings.ReplaceAll(bodyString, " ", ""), `"openapi":"3`) {
		openApiIndex = strings.Index(spec, `"openapi":`) - 1

		specClose = strings.LastIndex(spec, "]}") + 2

		var doc3 openapi3.T
		bodyBytes = []byte(spec[openApiIndex:specClose])
		_ = json.Unmarshal(bodyBytes, &doc3)
		if !strings.Contains(doc3.OpenAPI, "3") {
			specClose = strings.LastIndex(spec, "}") + 1
			bodyBytes = []byte(spec[openApiIndex:specClose])
			_ = json.Unmarshal(bodyBytes, &doc3)
			if !strings.Contains(doc3.OpenAPI, "3") {
				printErr("Error parsing JavaScript file for spec. Try saving the object as a JSON file and reference it locally.")
			}
		}
	} else {
		printErr("Error parsing JavaScript file for spec. Try saving the object as a JSON file and reference it locally.")
	}

	return bodyBytes
}

func UnmarshalSpec(bodyBytes []byte) (newDoc *openapi3.T) {
	var doc openapi2.T
	var doc3 openapi3.T

	format = strings.ToLower(format)
	if format == "js" || strings.HasSuffix(swaggerURL, ".js") {
		bodyBytes = ExtractSpecFromJS(bodyBytes)
	} else if format == "yaml" || format == "yml" || strings.HasSuffix(swaggerURL, ".yaml") || strings.HasSuffix(swaggerURL, ".yml") {
		_ = yaml.Unmarshal(bodyBytes, &doc)
		_ = yaml.Unmarshal(bodyBytes, &doc3)
	}

	_ = json.Unmarshal(bodyBytes, &doc)
	_ = json.Unmarshal(bodyBytes, &doc3)

	if strings.HasPrefix(doc3.OpenAPI, "3") {
		newDoc := &doc3
		return newDoc
	} else if strings.HasPrefix(doc.Swagger, "2") {
		newDoc, err := openapi2conv.ToV3(&doc)
		if err != nil {
			fmt.Printf("Error converting v2 document to v3: %s\n", err)
		}
		return newDoc
	} else if os.Args[1] == "brute" {
		var noDoc openapi3.T
		return &noDoc
	} else {
		die("Error parsing definition file.")
		return nil
	}
}

func init() {
	bruteCmd.PersistentFlags().StringVarP(&endpointWordlist, "wordlist", "w", "", "The file containing a list of paths to brute force for discovery.")
	bruteCmd.Flags().BoolVarP(&endpointOnly, "endpoint-only", "e", false, "Only return the identified endpoint.")
	bruteCmd.PersistentFlags().StringVarP(&bruteOutputFormat, "output-format", "F", "console", "Output format: 'console' (default) or 'json' for structured report.")
	bruteCmd.PersistentFlags().StringVarP(&bruteURLFile, "url-file", "U", "", "File containing a list of URLs to brute force (one per line).")
}
