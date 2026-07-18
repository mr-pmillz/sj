package brute

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/openapi"
	"github.com/mr-pmillz/sj/pkg/output"
	"gopkg.in/yaml.v3"
)

type Scanner struct {
	Client *httpclient.Client
	Cfg    *config.Config
}

const maxConsecutiveTransportErrors = 3

const (
	minimumExactWildcardResponses = 5
	minimumSizeWildcardResponses  = 8
)

func NewScanner(client *httpclient.Client, cfg *config.Config) *Scanner {
	return &Scanner{Client: client, Cfg: cfg}
}

// RunTargetsContext scans a target batch and returns reports in input order.
func (s *Scanner) RunTargetsContext(ctx context.Context, targets []string, workers int) ([]Report, error) {
	if workers < 1 || workers > config.MaxBruteWorkers {
		return nil, fmt.Errorf("workers must be between 1 and %d", config.MaxBruteWorkers)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets must not be empty")
	}
	for _, target := range targets {
		if _, _, err := normalizeTarget(target, s.Cfg.BasePath); err != nil {
			return nil, err
		}
	}
	workers = min(workers, len(targets))
	s.Cfg.BruteWorkers = workers
	batchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type targetJob struct {
		index int
		url   string
	}
	jobs := make(chan targetJob)
	reports := make([]Report, len(targets))
	var firstErr error
	var errOnce sync.Once
	recordError := func(index int, err error) {
		errOnce.Do(func() {
			firstErr = fmt.Errorf("scan target %d: %w", index+1, err)
			cancel()
		})
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for job := range jobs {
				report, err := s.RunTargetContext(batchCtx, job.url, false)
				if err != nil {
					recordError(job.index, err)
					return
				}
				reports[job.index] = report
			}
		}()
	}

dispatchLoop:
	for index, target := range targets {
		select {
		case jobs <- targetJob{index: index, url: target}:
		case <-batchCtx.Done():
			break dispatchLoop
		}
	}
	close(jobs)
	wait.Wait()
	if firstErr != nil {
		return reports, firstErr
	}
	if err := ctx.Err(); err != nil {
		return reports, fmt.Errorf("scan target batch: %w", err)
	}
	return reports, nil
}

func (s *Scanner) RunTarget(targetURL string, dumpSpec bool) Report {
	report, err := s.RunTargetContext(context.Background(), targetURL, dumpSpec)
	if err != nil {
		output.PrintErr("Brute scan failed for %s: %v", output.TerminalSafe(targetURL), err)
	}
	return report
}

func (s *Scanner) RunTargetContext(ctx context.Context, targetURL string, dumpSpec bool) (Report, error) {
	target, basePath, err := normalizeTarget(targetURL, s.Cfg.BasePath)
	if err != nil {
		return Report{Target: targetURL, SpecsFound: []SpecResult{}, Interesting: []Interesting{}}, err
	}
	candidates, err := s.candidates(target, basePath)
	if err != nil {
		return Report{Target: targetURL, SpecsFound: []SpecResult{}, Interesting: []Interesting{}}, err
	}
	output.PrintInfo("Sending up to %d requests. This could take a while...\n", len(candidates))
	matches, interesting, summary, err := s.findAllDefinitionFiles(ctx, candidates)
	report := makeReport(targetURL, matches, interesting, summary)
	if err != nil {
		return report, err
	}
	if structuredBruteOutput(s.Cfg.BruteOutputFormat) || s.Cfg.BruteAllFormats || s.Cfg.BruteWorkers > 1 {
		return report, nil
	}
	if err := s.printConsoleReport(report, matches, dumpSpec); err != nil {
		return report, err
	}
	return report, nil
}

func normalizeTarget(raw, configuredBasePath string) (string, string, error) {
	targetURL, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse target URL: %w", err)
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return "", "", fmt.Errorf("target must use http or https")
	}
	if targetURL.Host == "" || targetURL.User != nil {
		return "", "", fmt.Errorf("target must have a host and no user information")
	}
	basePath := openapi.NormalizeBasePath(configuredBasePath)
	if basePath == "" {
		basePath = openapi.NormalizeBasePath(targetURL.EscapedPath())
	}
	targetURL.Path = ""
	targetURL.RawPath = ""
	targetURL.RawQuery = ""
	targetURL.Fragment = ""
	return strings.TrimSuffix(targetURL.String(), "/"), basePath, nil
}

func (s *Scanner) candidates(target, basePath string) ([]string, error) {
	var candidates []string
	if s.Cfg.EndpointWordlist == "" {
		candidates = append(candidates, MakeURLs(target, basePath, PriorityURLs, "", true)...)
		candidates = append(candidates, MakeURLs(target, basePath, JSONEndpoints, "", false)...)
		candidates = append(candidates, MakeURLs(target, basePath, JavaScriptEndpoints, ".js", false)...)
		candidates = append(candidates, MakeURLs(target, basePath, JSONEndpoints, ".json", false)...)
		candidates = append(candidates, MakeURLs(target, basePath, JSONEndpoints, "/", false)...)
	} else {
		file, err := os.Open(s.Cfg.EndpointWordlist)
		if err != nil {
			return nil, fmt.Errorf("open endpoint wordlist: %w", err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			candidates = append(candidates, joinCandidateURL(target, basePath, line))
			if len(candidates) > s.Cfg.MaxCandidates {
				_ = file.Close()
				return nil, fmt.Errorf("wordlist exceeds %d candidate limit", s.Cfg.MaxCandidates)
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read endpoint wordlist: %w", scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close endpoint wordlist: %w", closeErr)
		}
	}
	candidates = deduplicateStrings(candidates)
	if len(candidates) > s.Cfg.MaxCandidates {
		return nil, fmt.Errorf("generated %d candidates, limit is %d", len(candidates), s.Cfg.MaxCandidates)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no brute-force candidates were generated")
	}
	return candidates, nil
}

func joinCandidateURL(target, basePath, endpoint string) string {
	return strings.TrimSuffix(target, "/") + "/" + strings.Trim(strings.TrimSuffix(basePath, "/")+"/"+strings.TrimPrefix(endpoint, "/"), "/")
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func makeReport(target string, matches []match, interesting []Interesting, summary Summary) Report {
	report := Report{Target: target, SpecsFound: []SpecResult{}, Interesting: interesting, Summary: summary}
	if report.Interesting == nil {
		report.Interesting = []Interesting{}
	}
	for _, found := range matches {
		report.SpecsFound = append(report.SpecsFound, SpecResult{
			URL: found.url, ContentType: found.contentType, OpenAPIVersion: found.version,
			Title: found.title, Description: found.description,
		})
	}
	report.Summary.SpecsFoundCount = len(matches)
	return report
}

func (s *Scanner) printConsoleReport(report Report, matches []match, dumpSpec bool) error {
	if len(matches) == 0 {
		output.PrintErr("\nNo definition file found for:\t%s", output.TerminalSafe(report.Target))
	} else if dumpSpec && !s.Cfg.EndpointOnly {
		definition, err := json.Marshal(matches[0].spec)
		if err != nil {
			return fmt.Errorf("marshal discovered specification: %w", err)
		}
		if s.Cfg.Outfile == "" {
			fmt.Println(string(definition))
		} else if err := writeBytesAtomically(s.Cfg.Outfile, definition); err != nil {
			return err
		}
	}
	if len(matches) > 1 {
		output.PrintInfo("\nFound %d definition files total:\n", len(matches))
		for _, found := range matches {
			output.PrintInfo("  - %s (OpenAPI %s, %s)\n", output.TerminalSafe(found.url), output.TerminalSafe(found.version), output.TerminalSafe(found.title))
		}
	}
	if len(report.Interesting) > 0 {
		output.PrintInfo("\nInteresting URLs found:\n")
		for _, interesting := range report.Interesting {
			output.PrintInfo("  [%d] %s (%s)\n", interesting.StatusCode, output.TerminalSafe(interesting.URL), output.TerminalSafe(interesting.ContentType))
		}
	}
	output.PrintInfo("\nSummary: %d URLs tested, %d specs found, %d interesting, %d wildcard false positives filtered, %d errors\n",
		report.Summary.URLsTested, len(matches), len(report.Interesting), report.Summary.FalsePositivesFiltered, report.Summary.Errors)
	return nil
}

func writeBytesAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sj-brute-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary output: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	return nil
}

type scanState struct {
	matches                    []match
	interesting                []Interesting
	summary                    Summary
	tested                     map[string]bool
	found                      map[string]bool
	variationQueue             []string
	consecutiveTransportErrors int
	responseFingerprints       []responseFingerprint
}

type responseFingerprint struct {
	url      string
	exactKey string
	sizeKey  string
}

func (s *Scanner) findAllDefinitionFiles(ctx context.Context, candidates []string) ([]match, []Interesting, Summary, error) {
	state := &scanState{tested: make(map[string]bool, len(candidates)), found: map[string]bool{}}
	for _, candidate := range candidates {
		state.tested[candidate] = true
	}
candidateLoop:
	for index, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return state.matches, state.interesting, state.summary, err
		}
		if s.Cfg.BruteWorkers <= 1 {
			fmt.Fprintf(os.Stderr, "\033[2K\rScanning: %d/%d", index+1, len(candidates))
		}
		s.processURL(ctx, candidate, state)
		if err := ctx.Err(); err != nil {
			return state.matches, state.interesting, state.summary, err
		}
		if state.transportErrorLimitReached() {
			break
		}
		for len(state.variationQueue) > 0 {
			variation := state.variationQueue[0]
			state.variationQueue = state.variationQueue[1:]
			s.processURL(ctx, variation, state)
			if err := ctx.Err(); err != nil {
				return state.matches, state.interesting, state.summary, err
			}
			if state.transportErrorLimitReached() {
				break candidateLoop
			}
		}
		if len(state.matches) > 0 && index >= len(PriorityURLs) {
			break
		}
	}
	if s.Cfg.BruteWorkers <= 1 {
		fmt.Fprint(os.Stderr, "\033[2K\r")
	}
	filterWildcardResponses(state)
	return state.matches, state.interesting, state.summary, nil
}

func (s *Scanner) processURL(ctx context.Context, targetURL string, state *scanState) {
	state.summary.URLsTested++
	body, contentType, status := s.Client.BruteFetchContext(ctx, targetURL)
	if status == 0 {
		state.summary.Errors++
		state.consecutiveTransportErrors++
		return
	}
	state.consecutiveTransportErrors = 0
	countStatus(&state.summary, status)
	if len(body) == 0 || status < 200 || status >= 300 {
		return
	}

	matchCount := len(state.matches)
	if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
		s.addSpec(targetURL, contentType, extracted, state)
	}
	if len(state.matches) == matchCount {
		s.addSpec(targetURL, contentType, body, state)
	}
	if len(state.matches) > matchCount {
		return
	}

	lowerType := strings.ToLower(contentType)
	if strings.Contains(lowerType, "html") || looksLikeHTML(body) {
		discoveredURLs := ExtractSpecURLsFromHTML(body, targetURL)
		for _, discovered := range discoveredURLs {
			s.queueVariation(discovered, state)
		}
	}
	if len(state.interesting) < s.Cfg.MaxCandidates {
		state.interesting = append(state.interesting, Interesting{URL: targetURL, StatusCode: status, ContentType: contentType})
		state.responseFingerprints = append(state.responseFingerprints, newResponseFingerprint(targetURL, status, contentType, body))
	}
}

func newResponseFingerprint(targetURL string, status int, contentType string, body []byte) responseFingerprint {
	baseType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	digest := sha256.Sum256(body)
	sizeKey := fmt.Sprintf("%d\x00%s\x00%d", status, baseType, len(body))
	return responseFingerprint{
		url:      targetURL,
		sizeKey:  sizeKey,
		exactKey: fmt.Sprintf("%s\x00%x", sizeKey, digest),
	}
}

func filterWildcardResponses(state *scanState) {
	if len(state.responseFingerprints) < minimumExactWildcardResponses {
		return
	}
	exactCounts := make(map[string]int)
	sizeCounts := make(map[string]int)
	for _, fingerprint := range state.responseFingerprints {
		exactCounts[fingerprint.exactKey]++
		sizeCounts[fingerprint.sizeKey]++
	}
	filteredURLs := make(map[string]struct{})
	for _, fingerprint := range state.responseFingerprints {
		if exactCounts[fingerprint.exactKey] >= minimumExactWildcardResponses || sizeCounts[fingerprint.sizeKey] >= minimumSizeWildcardResponses {
			filteredURLs[fingerprint.url] = struct{}{}
		}
	}
	if len(filteredURLs) == 0 {
		return
	}
	state.interesting = slices.DeleteFunc(state.interesting, func(item Interesting) bool {
		_, filtered := filteredURLs[item.URL]
		return filtered
	})
	state.summary.WildcardResponseDetected = true
	state.summary.FalsePositivesFiltered = len(filteredURLs)
}

func (state *scanState) transportErrorLimitReached() bool {
	if state.consecutiveTransportErrors < maxConsecutiveTransportErrors {
		return false
	}
	state.summary.TransportErrorLimitReached = true
	state.variationQueue = nil
	return true
}

func looksLikeHTML(body []byte) bool {
	trimmed := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 512)])))
	return strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html")
}

func countStatus(summary *Summary, status int) {
	switch {
	case status >= 200 && status < 300:
		summary.Responses2xx++
	case status >= 300 && status < 400:
		summary.Responses3xx++
	case status >= 400 && status < 500:
		summary.Responses4xx++
	case status >= 500:
		summary.Responses5xx++
	}
}

func (s *Scanner) addSpec(targetURL, contentType string, body []byte, state *scanState) {
	spec, version := TryParseAsSpec(body)
	if spec == nil || state.found[targetURL] {
		return
	}
	state.found[targetURL] = true
	found := match{url: targetURL, contentType: contentType, spec: spec, version: version}
	if spec.Info != nil {
		found.title = spec.Info.Title
		found.description = spec.Info.Description
	}
	state.matches = append(state.matches, found)
	output.PrintInfo("\nDefinition file found: %s (OpenAPI %s, %s)\n", output.TerminalSafe(targetURL), output.TerminalSafe(version), output.TerminalSafe(found.title))
	for _, variation := range GeneratePathVariations(targetURL) {
		s.queueVariation(variation, state)
	}
}

func (s *Scanner) queueVariation(candidate string, state *scanState) {
	if state.tested[candidate] || len(state.tested) >= s.Cfg.MaxCandidates {
		return
	}
	state.tested[candidate] = true
	state.variationQueue = append(state.variationQueue, candidate)
}

func TryParseAsSpec(body []byte) (*openapi3.T, string) {
	if document, version := parseOpenAPI3(body); document != nil {
		return document, version
	}
	if document := parseSwagger2(body); document != nil {
		return document, "2.0"
	}
	return nil, ""
}

func parseOpenAPI3(body []byte) (*openapi3.T, string) {
	var document openapi3.T
	if err := yaml.Unmarshal(body, &document); err != nil || !strings.HasPrefix(document.OpenAPI, "3") || document.Info == nil {
		return nil, ""
	}
	return &document, document.OpenAPI
}

func parseSwagger2(body []byte) *openapi3.T {
	document, err := openapi.DecodeSwagger2(body)
	if err != nil || !strings.HasPrefix(document.Swagger, "2") {
		return nil
	}
	converted, err := openapi2conv.ToV3(document)
	if err != nil || converted == nil || converted.Paths == nil {
		return nil
	}
	return converted
}

func structuredBruteOutput(format string) bool {
	switch strings.ToLower(format) {
	case "json", "jsonl", "csv", "txt":
		return true
	default:
		return false
	}
}
