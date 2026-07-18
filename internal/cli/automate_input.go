package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/store"
)

type automateSource struct {
	url       string
	localFile string
}

func (source automateSource) display() string {
	if source.url == "" {
		return source.localFile
	}
	parsed, err := url.Parse(source.url)
	if err != nil {
		return "remote specification"
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String()
}

func resolveAutomateSources(ctx context.Context, cfg *config.Config) ([]automateSource, error) {
	configured := 0
	for _, present := range []bool{cfg.SwaggerURL != "", cfg.LocalFile != "", cfg.AutomateURLFile != "", len(cfg.AutomateRunIDs) > 0} {
		if present {
			configured++
		}
	}
	if configured != 1 {
		return nil, fmt.Errorf("specify exactly one of --url, --local-file, --url-file, or --brute-run")
	}
	if len(cfg.AutomateRunIDs) > 0 {
		return automateSourcesFromRuns(ctx, cfg)
	}
	if cfg.AutomateURLFile == "" {
		return []automateSource{{url: cfg.SwaggerURL, localFile: cfg.LocalFile}}, nil
	}
	urls, err := loadAutomateURLs(cfg.AutomateURLFile, cfg.MaxSpecBytes, cfg.MaxAutomateTargets)
	if err != nil {
		return nil, err
	}
	sources := make([]automateSource, 0, len(urls))
	for _, specURL := range urls {
		sources = append(sources, automateSource{url: specURL})
	}
	return sources, nil
}

func automateSourcesFromRuns(ctx context.Context, cfg *config.Config) ([]automateSource, error) {
	if cfg.NoDatabase || strings.TrimSpace(cfg.DatabasePath) == "" {
		return nil, fmt.Errorf("--brute-run requires result database storage")
	}
	resultStore, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resultStore.Close() }()
	observations, err := resultStore.Observations(ctx, store.Query{RunIDs: cfg.AutomateRunIDs, Kinds: []string{"brute_spec"}, Limit: cfg.MaxAutomateTargets})
	if err != nil {
		return nil, fmt.Errorf("load stored brute results: %w", err)
	}
	collector := newAutomateURLCollector(cfg.MaxAutomateTargets)
	for index, observation := range observations {
		if err := collector.add(observation.URL, fmt.Sprintf("stored brute result %d", index+1)); err != nil {
			return nil, err
		}
	}
	if len(collector.urls) == 0 {
		return nil, fmt.Errorf("stored brute runs contain no discovered specifications")
	}
	sources := make([]automateSource, 0, len(collector.urls))
	for _, specURL := range collector.urls {
		sources = append(sources, automateSource{url: specURL})
	}
	return sources, nil
}

func loadAutomateURLs(path string, maxBytes int64, maxTargets int) ([]string, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("input size limit must be greater than zero")
	}
	if maxTargets <= 0 {
		return nil, fmt.Errorf("target limit must be greater than zero")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open automate input: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read automate input: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close automate input: %w", closeErr)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("automate input exceeds %d-byte limit", maxBytes)
	}

	collector := newAutomateURLCollector(maxTargets)
	extension := strings.ToLower(filepath.Ext(path))
	trimmed := bytes.TrimSpace(data)
	switch extension {
	case ".jsonl", ".ndjson":
		err = parseBruteJSONL(data, collector)
	default:
		switch {
		case len(trimmed) > 0 && trimmed[0] == '[':
			err = parseBruteJSON(trimmed, collector)
		case len(trimmed) > 0 && trimmed[0] == '{':
			if json.Valid(trimmed) {
				err = parseBruteJSONObject(trimmed, collector)
			} else {
				err = parseBruteJSONL(data, collector)
			}
		default:
			err = parsePlainURLList(data, collector)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(collector.urls) == 0 {
		return nil, fmt.Errorf("no specification URLs found in %q", path)
	}
	return collector.urls, nil
}

type automateURLCollector struct {
	maxTargets int
	seen       map[string]struct{}
	urls       []string
}

func newAutomateURLCollector(maxTargets int) *automateURLCollector {
	return &automateURLCollector{maxTargets: maxTargets, seen: make(map[string]struct{})}
}

func (collector *automateURLCollector) add(raw, location string) error {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: invalid specification URL: %w", location, err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s: specification URL must use http or https", location)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%s: specification URL must include a host", location)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s: specification URL must not contain user information", location)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%s: specification URL must not contain a fragment", location)
	}

	canonical := *parsed
	canonical.Scheme = strings.ToLower(canonical.Scheme)
	canonical.Host = strings.ToLower(canonical.Host)
	key := canonical.String()
	if _, exists := collector.seen[key]; exists {
		return nil
	}
	if len(collector.urls) >= collector.maxTargets {
		return fmt.Errorf("automate input exceeds %d target limit", collector.maxTargets)
	}
	collector.seen[key] = struct{}{}
	collector.urls = append(collector.urls, parsed.String())
	return nil
}

func parsePlainURLList(data []byte, collector *automateURLCollector) error {
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := collector.add(line, fmt.Sprintf("line %d", index+1)); err != nil {
			return err
		}
	}
	return nil
}

func parseBruteJSON(data []byte, collector *automateURLCollector) error {
	if len(data) == 0 {
		return nil
	}
	if data[0] == '[' {
		var reports []json.RawMessage
		if err := json.Unmarshal(data, &reports); err != nil {
			return fmt.Errorf("parse brute JSON report array: %w", err)
		}
		for index, report := range reports {
			if err := parseBruteJSONReport(report, fmt.Sprintf("report %d", index+1), collector); err != nil {
				return err
			}
		}
		return nil
	}
	return parseBruteJSONReport(data, "report", collector)
}

func parseBruteJSONObject(data []byte, collector *automateURLCollector) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("parse brute JSON object: %w", err)
	}
	if _, isReport := fields["specs_found"]; isReport {
		return parseBruteJSON(data, collector)
	}
	if _, isJSONLRow := fields["url"]; isJSONLRow {
		return parseBruteJSONL(data, collector)
	}
	return parseBruteJSON(data, collector)
}

func parseBruteJSONReport(data []byte, location string, collector *automateURLCollector) error {
	var report map[string]json.RawMessage
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parse brute JSON %s: %w", location, err)
	}
	rawSpecs, exists := report["specs_found"]
	if !exists {
		return fmt.Errorf("brute JSON %s does not contain specs_found", location)
	}
	var specs []brute.SpecResult
	if err := json.Unmarshal(rawSpecs, &specs); err != nil {
		return fmt.Errorf("parse brute JSON %s specs_found: %w", location, err)
	}
	for index, spec := range specs {
		if err := collector.add(spec.URL, fmt.Sprintf("%s specs_found[%d]", location, index)); err != nil {
			return err
		}
	}
	return nil
}

func parseBruteJSONL(data []byte, collector *automateURLCollector) error {
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		var row struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return fmt.Errorf("parse brute JSONL line %d: %w", index+1, err)
		}
		if row.URL == "" {
			return fmt.Errorf("parse brute JSONL line %d: missing url", index+1)
		}
		if err := collector.add(row.URL, fmt.Sprintf("line %d", index+1)); err != nil {
			return err
		}
	}
	return nil
}
