package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/brute"
)

type LoadOptions struct {
	MaxFileBytes int64
	MaxFiles     int
	MaxRecords   int
}

func DefaultLoadOptions() LoadOptions {
	return LoadOptions{MaxFileBytes: 256 * 1024 * 1024, MaxFiles: 10_000, MaxRecords: 1_000_000}
}

type loader struct {
	options     LoadOptions
	dataset     Dataset
	targets     map[string]struct{}
	discoveries map[string]Discovery
	interesting map[string]BruteObservation
	operations  map[string]Operation
	failures    map[string]Failure
	findings    map[string]ImportedFinding
	summaries   map[string]brute.Summary
	currentFile int
	currentKind string
}

func Load(inputs []string, options LoadOptions) (Dataset, error) {
	if len(inputs) == 0 {
		return Dataset{}, errors.New("at least one report input is required")
	}
	if options.MaxFileBytes <= 0 || options.MaxFiles <= 0 || options.MaxRecords <= 0 {
		return Dataset{}, errors.New("report input limits must be greater than zero")
	}
	paths, ignored, err := collectInputPaths(inputs, options.MaxFiles)
	if err != nil {
		return Dataset{}, err
	}
	state := &loader{
		options: options,
		dataset: Dataset{IgnoredFiles: ignored},
		targets: make(map[string]struct{}), discoveries: make(map[string]Discovery),
		interesting: make(map[string]BruteObservation), operations: make(map[string]Operation),
		failures: make(map[string]Failure), findings: make(map[string]ImportedFinding), summaries: make(map[string]brute.Summary),
	}
	for _, path := range paths {
		data, err := readBounded(path, options.MaxFileBytes)
		if err != nil {
			return Dataset{}, err
		}
		state.currentFile = len(state.dataset.Files)
		state.dataset.Files = append(state.dataset.Files, InputFile{Path: path})
		if err := state.parse(path, data); err != nil {
			return Dataset{}, fmt.Errorf("parse report input %s: %w", path, err)
		}
		state.dataset.Files[state.currentFile].Kind = state.currentKind
		state.currentKind = ""
	}
	state.finalize()
	return state.dataset, nil
}

func collectInputPaths(inputs []string, maxFiles int) ([]string, []string, error) {
	var paths []string
	var ignored []string
	seen := make(map[string]struct{})
	add := func(path string, explicit bool) error {
		cleaned := filepath.Clean(path)
		if _, exists := seen[cleaned]; exists {
			return nil
		}
		seen[cleaned] = struct{}{}
		extension := strings.ToLower(filepath.Ext(cleaned))
		if extension != ".json" && extension != ".jsonl" && extension != ".csv" && extension != ".txt" {
			if explicit {
				return fmt.Errorf("unsupported report input %s", cleaned)
			}
			ignored = append(ignored, cleaned)
			return nil
		}
		paths = append(paths, cleaned)
		if len(paths)+len(ignored) > maxFiles {
			return fmt.Errorf("report input exceeds %d-file limit", maxFiles)
		}
		return nil
	}
	for _, input := range inputs {
		info, err := os.Stat(input)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect report input %s: %w", input, err)
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("report input is not a regular file: %s", input)
			}
			if err := add(input, true); err != nil {
				return nil, nil, err
			}
			continue
		}
		err = filepath.WalkDir(input, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				cleaned := filepath.Clean(path)
				if _, exists := seen[cleaned]; exists {
					return nil
				}
				seen[cleaned] = struct{}{}
				ignored = append(ignored, cleaned)
				if len(paths)+len(ignored) > maxFiles {
					return fmt.Errorf("report input exceeds %d-file limit", maxFiles)
				}
				return nil
			}
			return add(path, false)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walk report input %s: %w", input, err)
		}
	}
	sort.Strings(paths)
	sort.Strings(ignored)
	if len(paths) == 0 {
		return nil, nil, errors.New("no supported report result files found")
	}
	return paths, ignored, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("report input %s exceeds %d-byte limit", path, limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s: %w", path, closeErr)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("report input %s exceeds %d-byte limit", path, limit)
	}
	return data, nil
}

func (state *loader) parse(path string, data []byte) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		state.currentKind = "json"
		return state.parseJSON(data)
	case ".jsonl":
		state.currentKind = "jsonl"
		return state.parseJSONL(data)
	case ".csv":
		state.currentKind = "csv"
		return state.parseCSV(data)
	case ".txt":
		state.currentKind = "brute-text"
		return state.parseBruteText(data)
	default:
		return errors.New("unsupported report input extension")
	}
}

func (state *loader) parseJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return errors.New("empty JSON input")
	}
	if trimmed[0] == '[' {
		var records []json.RawMessage
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return err
		}
		for _, record := range records {
			if err := state.parseJSONRecord(record); err != nil {
				return err
			}
		}
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return err
	}
	if raw, exists := object["results"]; exists {
		var operations []Operation
		if err := json.Unmarshal(raw, &operations); err != nil {
			return fmt.Errorf("decode automate results: %w", err)
		}
		state.currentKind = "automate-json"
		for _, operation := range operations {
			if err := state.addOperation(operation); err != nil {
				return err
			}
		}
		return nil
	}
	if raw, exists := object["probes"]; exists {
		var probes []struct {
			Method            string `json:"method"`
			URL               string `json:"url"`
			BaselineURL       string `json:"baseline_url"`
			Case              string `json:"case"`
			Category          string `json:"category"`
			Identity          string `json:"identity"`
			Guidance          string `json:"guidance"`
			Status            int    `json:"status"`
			ContentType       string `json:"content_type"`
			RequestBody       string `json:"request_body"`
			ResponseBody      string `json:"response_body"`
			ResponseTruncated bool   `json:"response_truncated"`
		}
		if err := json.Unmarshal(raw, &probes); err != nil {
			return fmt.Errorf("decode fuzz probes: %w", err)
		}
		state.currentKind = "fuzz-json"
		for _, probe := range probes {
			parsed, _ := url.Parse(probe.URL)
			source := ""
			target := probe.URL
			if parsed != nil {
				source = parsed.Scheme + "://" + parsed.Host
				target = parsed.EscapedPath()
			}
			if err := state.addOperation(Operation{
				Source: source, Method: probe.Method, Status: probe.Status, Target: target, URL: probe.URL,
				BaselineURL: probe.BaselineURL, Case: probe.Case, Category: probe.Category, Identity: probe.Identity, Guidance: probe.Guidance,
				ContentType: probe.ContentType, RequestBody: probe.RequestBody, ResponseBody: probe.ResponseBody,
				ResponseTruncated: probe.ResponseTruncated,
			}); err != nil {
				return err
			}
		}
		if findingsRaw, found := object["findings"]; found {
			var findings []ImportedFinding
			if err := json.Unmarshal(findingsRaw, &findings); err != nil {
				return fmt.Errorf("decode fuzz findings: %w", err)
			}
			for _, finding := range findings {
				if err := state.addImportedFinding(finding); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if raw, exists := object["reports"]; exists {
		var reports []brute.Report
		if err := json.Unmarshal(raw, &reports); err != nil {
			return fmt.Errorf("decode brute reports: %w", err)
		}
		state.currentKind = "brute-json"
		for _, report := range reports {
			if err := state.addBruteReport(report); err != nil {
				return err
			}
		}
		return nil
	}
	return state.parseJSONMap(object)
}

func (state *loader) parseJSONL(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := state.parseJSONRecord(raw); err != nil {
			return err
		}
	}
}

func (state *loader) parseJSONRecord(raw json.RawMessage) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	return state.parseJSONMap(object)
}

func (state *loader) parseJSONMap(object map[string]json.RawMessage) error {
	if rawType, exists := object["type"]; exists {
		var recordType string
		if err := json.Unmarshal(rawType, &recordType); err != nil {
			return err
		}
		switch recordType {
		case "probe":
			var encoded struct {
				Method            string `json:"method"`
				URL               string `json:"url"`
				BaselineURL       string `json:"baseline_url"`
				Case              string `json:"case"`
				Category          string `json:"category"`
				Identity          string `json:"identity"`
				Guidance          string `json:"guidance"`
				ContentType       string `json:"content_type"`
				RequestBody       string `json:"request_body"`
				ResponseBody      string `json:"response_body"`
				Status            int    `json:"status"`
				ResponseTruncated bool   `json:"response_truncated"`
			}
			if err := json.Unmarshal(object["probe"], &encoded); err != nil {
				return fmt.Errorf("decode fuzz probe: %w", err)
			}
			parsed, _ := url.Parse(encoded.URL)
			source, target := "", encoded.URL
			if parsed != nil {
				source, target = parsed.Scheme+"://"+parsed.Host, parsed.EscapedPath()
			}
			state.currentKind = "fuzz-jsonl"
			return state.addOperation(Operation{
				Source: source, Method: encoded.Method, Status: encoded.Status, Target: target, URL: encoded.URL,
				BaselineURL: encoded.BaselineURL, Case: encoded.Case, Category: encoded.Category, Identity: encoded.Identity, Guidance: encoded.Guidance,
				ContentType: encoded.ContentType, RequestBody: encoded.RequestBody, ResponseBody: encoded.ResponseBody,
				ResponseTruncated: encoded.ResponseTruncated,
			})
		case "finding":
			var finding ImportedFinding
			if err := json.Unmarshal(object["finding"], &finding); err != nil {
				return fmt.Errorf("decode fuzz finding: %w", err)
			}
			state.currentKind = "fuzz-jsonl"
			return state.addImportedFinding(finding)
		}
	}
	if _, exists := object["specs_found"]; exists {
		var report brute.Report
		data, _ := json.Marshal(object)
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		state.currentKind = "brute-json"
		return state.addBruteReport(report)
	}
	if _, hasMethod := object["method"]; hasMethod {
		if _, hasStatus := object["status"]; hasStatus {
			var operation Operation
			data, _ := json.Marshal(object)
			if err := json.Unmarshal(data, &operation); err != nil {
				return err
			}
			state.currentKind = "automate-jsonl"
			return state.addOperation(operation)
		}
	}
	if _, hasError := object["error"]; hasError {
		var failure Failure
		data, _ := json.Marshal(object)
		if err := json.Unmarshal(data, &failure); err != nil {
			return err
		}
		state.currentKind = "automate-failures"
		return state.addFailure(failure)
	}
	if _, hasURL := object["url"]; hasURL {
		var record struct {
			Target  string `json:"target"`
			URL     string `json:"url"`
			Version string `json:"openapi_version"`
			Title   string `json:"title"`
		}
		data, _ := json.Marshal(object)
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		state.currentKind = "brute-jsonl"
		if err := state.addTarget(record.Target); err != nil {
			return err
		}
		return state.addDiscovery(Discovery{Target: record.Target, URL: record.URL, Version: record.Version, Title: record.Title})
	}
	return errors.New("unrecognized sj JSON result schema")
}

func (state *loader) parseCSV(data []byte) error {
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("empty CSV input")
	}
	header := make(map[string]int, len(records[0]))
	for index, name := range records[0] {
		header[strings.ToLower(strings.TrimSpace(name))] = index
	}
	if _, automate := header["method"]; automate {
		state.currentKind = "automate-csv"
		for rowIndex, row := range records[1:] {
			status, err := strconv.Atoi(csvValue(row, header, "status"))
			if err != nil {
				return fmt.Errorf("row %d: invalid status: %w", rowIndex+2, err)
			}
			truncated, _ := strconv.ParseBool(csvValue(row, header, "response_truncated"))
			if err := state.addOperation(Operation{
				Source: csvValue(row, header, "source"), Method: csvValue(row, header, "method"), Status: status,
				Target: csvValue(row, header, "target"), URL: csvValue(row, header, "url"), ContentType: csvValue(row, header, "content_type"),
				RequestBody: csvValue(row, header, "request_body"), ResponseBody: csvValue(row, header, "response_body"), ResponseTruncated: truncated,
			}); err != nil {
				return err
			}
		}
		return nil
	}
	if _, bruteOutput := header["url"]; bruteOutput {
		state.currentKind = "brute-csv"
		for _, row := range records[1:] {
			target := csvValue(row, header, "target")
			if err := state.addTarget(target); err != nil {
				return err
			}
			if err := state.addDiscovery(Discovery{Target: target, URL: csvValue(row, header, "url"), Version: csvValue(row, header, "openapi_version"), Title: csvValue(row, header, "title")}); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("unrecognized sj CSV result schema")
}

func csvValue(row []string, header map[string]int, name string) string {
	index, exists := header[name]
	if !exists || index >= len(row) {
		return ""
	}
	return row[index]
}

func (state *loader) parseBruteText(data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	currentTarget := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# Target:") {
			currentTarget = strings.TrimSpace(strings.TrimPrefix(line, "# Target:"))
			if err := state.addTarget(currentTarget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if err := state.addDiscovery(Discovery{Target: currentTarget, URL: line}); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func (state *loader) addBruteReport(report brute.Report) error {
	if err := state.addTarget(report.Target); err != nil {
		return err
	}
	if existing, found := state.summaries[report.Target]; !found || report.Summary.URLsTested > existing.URLsTested {
		state.summaries[report.Target] = report.Summary
	}
	for _, spec := range report.SpecsFound {
		if err := state.addDiscovery(Discovery{Target: report.Target, URL: spec.URL, Version: spec.OpenAPIVersion, Title: spec.Title}); err != nil {
			return err
		}
	}
	for _, item := range report.Interesting {
		if err := state.addInteresting(BruteObservation{Target: report.Target, URL: item.URL, Status: item.StatusCode, ContentType: item.ContentType}); err != nil {
			return err
		}
	}
	return nil
}

func (state *loader) addTarget(target string) error {
	if target == "" {
		return nil
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	state.targets[target] = struct{}{}
	return nil
}

func (state *loader) addDiscovery(discovery Discovery) error {
	if discovery.URL == "" {
		return nil
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	if existing, found := state.discoveries[discovery.URL]; !found || existing.Version == "" {
		state.discoveries[discovery.URL] = discovery
	}
	return nil
}

func (state *loader) addInteresting(item BruteObservation) error {
	if item.URL == "" {
		return nil
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	key := fmt.Sprintf("%s\x00%d", item.URL, item.Status)
	state.interesting[key] = item
	return nil
}

func (state *loader) addOperation(operation Operation) error {
	if operation.Origin == "" {
		if strings.HasPrefix(state.currentKind, "fuzz-") {
			operation.Origin = "fuzz"
		} else {
			operation.Origin = "automate"
		}
	}
	operation.Method = strings.ToUpper(strings.TrimSpace(operation.Method))
	if operation.Method == "" || operation.Target == "" || operation.Status < 0 || operation.Status > 999 {
		return fmt.Errorf("invalid automate result for %q %q", operation.Method, operation.Target)
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	key := strings.Join([]string{
		operation.Source, operation.Method, strconv.Itoa(operation.Status), operation.Target, operation.URL,
		operation.BaselineURL, operation.Case, operation.Identity,
	}, "\x00")
	state.operations[key] = operation
	return nil
}

func (state *loader) addFailure(failure Failure) error {
	if failure.Source == "" || failure.Error == "" {
		return errors.New("invalid automate failure record")
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	state.failures[failure.Source+"\x00"+failure.Error] = failure
	return nil
}

func (state *loader) addImportedFinding(finding ImportedFinding) error {
	if strings.TrimSpace(finding.Severity) == "" || strings.TrimSpace(finding.Title) == "" {
		return errors.New("invalid imported fuzz finding")
	}
	if err := state.countRecord(); err != nil {
		return err
	}
	state.findings[importedFindingKey(finding)] = finding
	return nil
}

func (state *loader) countRecord() error {
	state.dataset.RawRecords++
	state.dataset.Files[state.currentFile].Records++
	if state.dataset.RawRecords > state.options.MaxRecords {
		return fmt.Errorf("report input exceeds %d-record limit", state.options.MaxRecords)
	}
	return nil
}

func (state *loader) finalize() {
	state.dataset.Targets = sortedKeys(state.targets)
	state.dataset.Discoveries = sortedValues(state.discoveries, func(item Discovery) string { return item.URL })
	state.dataset.BruteObservations = sortedValues(state.interesting, func(item BruteObservation) string { return item.URL + fmt.Sprint(item.Status) })
	state.dataset.Operations = sortedValues(state.operations, func(item Operation) string {
		return strings.Join([]string{item.Source, item.Method, fmt.Sprint(item.Status), item.Target, item.URL}, "\x00")
	})
	state.dataset.Failures = sortedValues(state.failures, func(item Failure) string { return item.Source + item.Error })
	state.dataset.ImportedFindings = sortedValues(state.findings, importedFindingKey)
	for _, summary := range state.summaries {
		state.dataset.BruteURLsTested += summary.URLsTested
		state.dataset.BruteRequestErrors += summary.Errors
		state.dataset.BruteFalsePositivesFiltered += summary.FalsePositivesFiltered
		if summary.TransportErrorLimitReached {
			state.dataset.TransportLimitedTargets++
		}
		if summary.WAFChallengeDetected {
			state.dataset.WAFChallengedTargets++
		}
		state.dataset.WAFChallengeResponses += summary.WAFChallengeResponses
		state.dataset.BruteReferencesRejected += summary.ReferencesRejected
		state.dataset.BruteReferencesSkipped += summary.ReferencesSkipped
	}
	unique := len(state.dataset.Targets) + len(state.dataset.Discoveries) + len(state.dataset.BruteObservations) + len(state.dataset.Operations) + len(state.dataset.Failures) + len(state.dataset.ImportedFindings)
	state.dataset.DuplicateRecords = max(0, state.dataset.RawRecords-unique)
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedValues[T any](values map[string]T, key func(T) string) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return key(result[i]) < key(result[j]) })
	return result
}
