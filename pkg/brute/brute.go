package brute

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	Client    *httpclient.Client
	Cfg       *config.Config
	runTarget func(context.Context, string, bool) (Report, error)
}

type PartialBatchError struct {
	failures []error
}

func NewPartialBatchError(failures ...error) *PartialBatchError {
	return &PartialBatchError{failures: append([]error(nil), failures...)}
}

func (failure *PartialBatchError) Error() string {
	return fmt.Sprintf("%d target scans failed after isolated execution: %v", len(failure.failures), errors.Join(failure.failures...))
}

func (failure *PartialBatchError) Unwrap() []error {
	return append([]error(nil), failure.failures...)
}

const maxConsecutiveTransportErrors = 3

const (
	minimumExactWildcardResponses = 5
	minimumSizeWildcardResponses  = 8
	maxReferenceDepth             = 3
	maxReferencesPerResponse      = 32
	maxConsecutiveWAFChallenges   = 3
	maxConsecutiveUnavailable     = 3
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
	type targetJob struct {
		index int
		url   string
	}
	jobs := make(chan targetJob)
	reports := make([]Report, len(targets))
	targetErrors := make([]error, len(targets))
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for job := range jobs {
				report, err := s.runTargetContext(ctx, job.url, false)
				reports[job.index] = report
				if err != nil {
					targetErrors[job.index] = fmt.Errorf("scan target %d: %w", job.index+1, err)
				}
			}
		}()
	}

dispatchLoop:
	for index, target := range targets {
		select {
		case jobs <- targetJob{index: index, url: target}:
		case <-ctx.Done():
			break dispatchLoop
		}
	}
	close(jobs)
	wait.Wait()
	if err := ctx.Err(); err != nil {
		return reports, errors.Join(fmt.Errorf("scan target batch: %w", err), errors.Join(targetErrors...))
	}
	failures := make([]error, 0)
	for _, targetErr := range targetErrors {
		if targetErr != nil {
			failures = append(failures, targetErr)
		}
	}
	if len(failures) > 0 {
		return reports, NewPartialBatchError(failures...)
	}
	return reports, nil
}

func (s *Scanner) runTargetContext(ctx context.Context, targetURL string, dumpSpec bool) (Report, error) {
	if s.runTarget != nil {
		return s.runTarget(ctx, targetURL, dumpSpec)
	}
	return s.RunTargetContext(ctx, targetURL, dumpSpec)
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
	if report.Summary.WAFChallengeDetected {
		output.PrintWarn("Browser/WAF challenges were detected in %d response(s); discovery results may be incomplete. For an authorized assessment, replay the exact solved browser User-Agent and Cookie headers from the same network path.", report.Summary.WAFChallengeResponses)
	}
	if report.Summary.WAFChallengeLimitReached {
		output.PrintWarn("Discovery stopped after prioritized candidates returned sustained browser/WAF challenges; the target was not exposing its underlying content.")
	}
	if report.Summary.RateLimitReached {
		output.PrintWarn("Discovery stopped after HTTP 429 to avoid exhausting the target's advertised request capacity.")
	}
	if report.Summary.UnavailableLimitReached {
		output.PrintWarn("Discovery stopped after %d consecutive identical 502/503/504 responses; the target was uniformly unavailable.", maxConsecutiveUnavailable)
	}
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
	output.PrintInfo("\nSummary: %d URLs tested, %d specs found, %d interesting, %d wildcard false positives filtered, %d WAF challenges, %d references rejected, %d references skipped, %d errors\n",
		report.Summary.URLsTested, len(matches), len(report.Interesting), report.Summary.FalsePositivesFiltered, report.Summary.WAFChallengeResponses,
		report.Summary.ReferencesRejected, report.Summary.ReferencesSkipped, report.Summary.Errors)
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
	matches                     []match
	interesting                 []Interesting
	summary                     Summary
	tested                      map[string]bool
	known                       map[string]bool
	queued                      map[string]bool
	found                       map[string]bool
	variationQueue              []scanCandidate
	consecutiveTransportErrors  int
	consecutiveWAFChallenges    int
	minimumWAFChallengeCoverage int
	consecutiveUnavailable      int
	lastUnavailableShape        string
	responseFingerprints        []responseFingerprint
}

type scanCandidate struct {
	url            string
	referenceDepth int
}

type responseFingerprint struct {
	url      string
	exactKey string
	sizeKey  string
}

func (s *Scanner) findAllDefinitionFiles(ctx context.Context, candidates []string) ([]match, []Interesting, Summary, error) {
	state := &scanState{
		tested:                      make(map[string]bool, len(candidates)),
		known:                       make(map[string]bool, len(candidates)),
		queued:                      make(map[string]bool),
		found:                       make(map[string]bool),
		minimumWAFChallengeCoverage: min(len(candidates), len(PriorityURLs)),
	}
	for _, candidate := range candidates {
		state.known[candidate] = true
	}
candidateLoop:
	for index, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return state.matches, state.interesting, state.summary, err
		}
		if s.Cfg.BruteWorkers <= 1 {
			fmt.Fprintf(os.Stderr, "\033[2K\rScanning: %d/%d", index+1, len(candidates))
		}
		s.processCandidate(ctx, scanCandidate{url: candidate}, state)
		if err := ctx.Err(); err != nil {
			return state.matches, state.interesting, state.summary, err
		}
		if state.scanLimitReached() {
			break
		}
		for len(state.variationQueue) > 0 {
			variation := state.variationQueue[0]
			state.variationQueue = state.variationQueue[1:]
			s.processCandidate(ctx, variation, state)
			if err := ctx.Err(); err != nil {
				return state.matches, state.interesting, state.summary, err
			}
			if state.scanLimitReached() {
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
	s.processCandidate(ctx, scanCandidate{url: targetURL}, state)
}

func (s *Scanner) processCandidate(ctx context.Context, candidate scanCandidate, state *scanState) {
	if state.tested == nil {
		state.tested = make(map[string]bool)
	}
	if state.known == nil {
		state.known = make(map[string]bool)
	}
	if state.queued == nil {
		state.queued = make(map[string]bool)
	}
	delete(state.queued, candidate.url)
	if state.tested[candidate.url] {
		return
	}
	state.tested[candidate.url] = true
	state.known[candidate.url] = true
	targetURL := candidate.url
	state.summary.URLsTested++
	body, contentType, status, metadata := s.Client.BruteFetchWithMetadataContext(ctx, targetURL)
	if status == 0 {
		state.resetUnavailableSequence()
		state.recordWAFChallengeLimit(false)
		state.summary.Errors++
		state.consecutiveTransportErrors++
		return
	}
	state.consecutiveTransportErrors = 0
	countStatus(&state.summary, status)
	if len(body) == 0 {
		state.recordResponseLimit(status, contentType, body, false, metadata.Header)
		state.recordWAFChallengeLimit(false)
		return
	}
	if status < 200 || status >= 300 {
		challenge := recordWAFChallenge(body, contentType, status, &state.summary)
		state.recordResponseLimit(status, contentType, body, challenge, metadata.Header)
		state.recordWAFChallengeLimit(challenge)
		return
	}
	state.recordResponseLimit(status, contentType, body, false, metadata.Header)

	matchCount := len(state.matches)
	if extracted, ok := openapi.ExtractJSONFromJSSpec(body); ok {
		s.addSpec(targetURL, contentType, extracted, candidate.referenceDepth, state)
	}
	if len(state.matches) == matchCount {
		s.addSpec(targetURL, contentType, body, candidate.referenceDepth, state)
	}
	if len(state.matches) > matchCount {
		state.recordWAFChallengeLimit(false)
		return
	}
	challenge := recordWAFChallenge(body, contentType, status, &state.summary)
	state.recordWAFChallengeLimit(challenge)
	if challenge {
		return
	}

	references := extractDiscoveryReferences(body, contentType, targetURL)
	state.summary.ReferencesRejected += references.Rejected
	state.summary.ReferencesSkipped += references.Skipped
	for _, discovered := range references.URLs {
		s.queueReference(discovered, candidate.referenceDepth+1, state)
	}
	if len(state.interesting) < s.Cfg.MaxCandidates {
		state.interesting = append(state.interesting, Interesting{URL: targetURL, StatusCode: status, ContentType: contentType})
		state.responseFingerprints = append(state.responseFingerprints, newResponseFingerprint(targetURL, status, contentType, body))
	}
}

func recordWAFChallenge(body []byte, contentType string, status int, summary *Summary) bool {
	if !looksLikeWAFChallenge(body, contentType, status) {
		return false
	}
	summary.WAFChallengeDetected = true
	summary.WAFChallengeResponses++
	return true
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

func (state *scanState) scanLimitReached() bool {
	if state.transportErrorLimitReached() {
		return true
	}
	if !state.summary.RateLimitReached && !state.summary.UnavailableLimitReached && !state.summary.WAFChallengeLimitReached {
		return false
	}
	state.variationQueue = nil
	return true
}

func (state *scanState) recordWAFChallengeLimit(challenge bool) {
	if !challenge {
		state.consecutiveWAFChallenges = 0
		return
	}
	state.consecutiveWAFChallenges++
	if state.consecutiveWAFChallenges >= maxConsecutiveWAFChallenges && state.summary.URLsTested >= state.minimumWAFChallengeCoverage {
		state.summary.WAFChallengeLimitReached = true
	}
}

func (state *scanState) recordResponseLimit(
	status int,
	contentType string,
	body []byte,
	wafChallenge bool,
	header http.Header,
) {
	if status == http.StatusTooManyRequests || bruteRateCapacityDepleted(header) {
		state.summary.RateLimitReached = true
		state.resetUnavailableSequence()
		return
	}
	if wafChallenge {
		state.resetUnavailableSequence()
		return
	}
	if status != http.StatusBadGateway && status != http.StatusServiceUnavailable && status != http.StatusGatewayTimeout {
		state.resetUnavailableSequence()
		return
	}
	shape := newResponseFingerprint("", status, contentType, body).sizeKey
	if shape != state.lastUnavailableShape {
		state.lastUnavailableShape = shape
		state.consecutiveUnavailable = 1
		return
	}
	state.consecutiveUnavailable++
	if state.consecutiveUnavailable >= maxConsecutiveUnavailable {
		state.summary.UnavailableLimitReached = true
	}
}

func bruteRateCapacityDepleted(header http.Header) bool {
	for _, name := range []string{"RateLimit-Remaining", "X-RateLimit-Remaining"} {
		for _, raw := range header.Values(name) {
			field, _, _ := strings.Cut(strings.TrimSpace(raw), ";")
			field, _, _ = strings.Cut(field, ",")
			remaining, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
			if err == nil && remaining <= 1 {
				return true
			}
		}
	}
	return false
}

func (state *scanState) resetUnavailableSequence() {
	state.consecutiveUnavailable = 0
	state.lastUnavailableShape = ""
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

func (s *Scanner) addSpec(targetURL, contentType string, body []byte, referenceDepth int, state *scanState) {
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
		s.queueVariation(variation, referenceDepth, state)
	}
}

func (s *Scanner) queueReference(candidate string, referenceDepth int, state *scanState) {
	if referenceDepth > maxReferenceDepth {
		state.summary.ReferencesSkipped++
		return
	}
	s.queueCandidate(scanCandidate{url: candidate, referenceDepth: referenceDepth}, state)
}

func (s *Scanner) queueVariation(candidate string, referenceDepth int, state *scanState) {
	// Bulk candidates retain their original priority. Only genuinely new path
	// variants should interrupt that ordering after a specification is found.
	if state.known[candidate] {
		return
	}
	s.queueCandidate(scanCandidate{url: candidate, referenceDepth: referenceDepth}, state)
}

func (s *Scanner) queueCandidate(candidate scanCandidate, state *scanState) {
	if state.tested[candidate.url] || state.queued[candidate.url] {
		return
	}
	if !state.known[candidate.url] {
		if len(state.known) >= s.Cfg.MaxCandidates {
			state.summary.ReferencesSkipped++
			return
		}
		state.known[candidate.url] = true
	}
	state.queued[candidate.url] = true
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
