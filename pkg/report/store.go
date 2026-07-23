package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/brute"
	"github.com/mr-pmillz/sj/pkg/store"
)

func DatasetFromStoredObservations(observations []store.Observation) (Dataset, error) {
	return DatasetFromStoredResults(observations, nil)
}

func DatasetFromStoredResults(observations []store.Observation, storedFindings []store.Finding) (Dataset, error) {
	dataset := Dataset{RawRecords: len(observations)}
	targets := make(map[string]struct{})
	discoveries := make(map[string]Discovery)
	interesting := make(map[string]BruteObservation)
	operations := make(map[string]Operation)
	successfulSources := make(map[string]struct{})
	failures := make(map[string]Failure)
	importedFindings := make(map[string]ImportedFinding)
	summaries := make(map[string]brute.Summary)
	for index, observation := range observations {
		switch observation.Kind {
		case "brute_spec":
			metadata, err := observationMetadata(observation.Metadata)
			if err != nil {
				return Dataset{}, fmt.Errorf("decode stored observation %d: %w", index+1, err)
			}
			targets[observation.Source] = struct{}{}
			discoveries[observation.URL] = Discovery{
				Target: observation.Source, URL: observation.URL,
				Version: stringMetadata(metadata, "openapi_version"), Title: stringMetadata(metadata, "title"),
			}
		case "brute_interesting":
			targets[observation.Source] = struct{}{}
			key := observation.URL + "\x00" + strconv.Itoa(observation.Status)
			interesting[key] = BruteObservation{Target: observation.Source, URL: observation.URL, Status: observation.Status, ContentType: observation.ContentType}
		case "brute_summary":
			var summary brute.Summary
			if err := decodeMetadata(observation.Metadata, &summary); err != nil {
				return Dataset{}, fmt.Errorf("decode stored brute summary %d: %w", index+1, err)
			}
			summaries[observation.Source] = summary
		case "automate":
			operation := Operation{
				Origin: "automate",
				Source: observation.Source, Method: strings.ToUpper(observation.Method), Status: observation.Status,
				Target: observation.Path, URL: observation.URL, ContentType: observation.ContentType,
				RequestBody: string(observation.RequestBody), ResponseBody: string(observation.ResponseBody),
				ResponseTruncated: observation.ResponseTruncated,
			}
			key := strings.Join([]string{operation.Source, operation.Method, operation.URL, operation.Target, strconv.Itoa(operation.Status)}, "\x00")
			operations[key] = operation
			successfulSources[operation.Source] = struct{}{}
		case "fuzz_probe":
			metadata, err := observationMetadata(observation.Metadata)
			if err != nil {
				return Dataset{}, fmt.Errorf("decode stored fuzz observation %d: %w", index+1, err)
			}
			parsed, _ := url.Parse(observation.URL)
			source, target := "", observation.URL
			if parsed != nil {
				source = parsed.Scheme + "://" + parsed.Host
				target = parsed.EscapedPath()
			}
			operation := Operation{
				Origin: "fuzz", Source: source, Method: strings.ToUpper(observation.Method), Status: observation.Status,
				Target: target, URL: observation.URL, BaselineURL: stringMetadata(metadata, "baseline_url"),
				Case: stringMetadata(metadata, "case"), Category: stringMetadata(metadata, "category"),
				Identity: stringMetadata(metadata, "identity"), Guidance: stringMetadata(metadata, "guidance"), ContentType: observation.ContentType,
				RequestBody: string(observation.RequestBody), ResponseBody: string(observation.ResponseBody),
				ResponseTruncated: observation.ResponseTruncated,
			}
			key := strings.Join([]string{
				operation.Source, operation.Method, operation.URL, operation.Target, strconv.Itoa(operation.Status),
				operation.BaselineURL, operation.Case, operation.Identity,
			}, "\x00")
			operations[key] = operation
		case "automate_failure":
			metadata, err := observationMetadata(observation.Metadata)
			if err != nil {
				return Dataset{}, fmt.Errorf("decode stored automate failure %d: %w", index+1, err)
			}
			failure := Failure{Source: observation.Source, Error: stringMetadata(metadata, "error")}
			failures[failure.Source+"\x00"+failure.Error] = failure
		}
	}
	for target := range targets {
		dataset.Targets = append(dataset.Targets, target)
	}
	for _, item := range discoveries {
		dataset.Discoveries = append(dataset.Discoveries, item)
	}
	for _, item := range interesting {
		dataset.BruteObservations = append(dataset.BruteObservations, item)
	}
	for _, item := range operations {
		dataset.Operations = append(dataset.Operations, item)
	}
	for _, item := range failures {
		if item.Source != "" {
			if _, succeeded := successfulSources[item.Source]; succeeded {
				continue
			}
		}
		dataset.Failures = append(dataset.Failures, item)
	}
	for _, summary := range summaries {
		dataset.BruteURLsTested += summary.URLsTested
		dataset.BruteRequestErrors += summary.Errors
		dataset.BruteFalsePositivesFiltered += summary.FalsePositivesFiltered
		if summary.TransportErrorLimitReached {
			dataset.TransportLimitedTargets++
		}
		if summary.WAFChallengeDetected {
			dataset.WAFChallengedTargets++
		}
		dataset.WAFChallengeResponses += summary.WAFChallengeResponses
		if summary.WAFChallengeLimitReached {
			dataset.WAFChallengeLimitedTargets++
		}
		dataset.BruteReferencesRejected += summary.ReferencesRejected
		dataset.BruteReferencesSkipped += summary.ReferencesSkipped
		if summary.RateLimitReached {
			dataset.RateLimitedTargets++
		}
		if summary.UnavailableLimitReached {
			dataset.UnavailableLimitedTargets++
		}
	}
	sort.Strings(dataset.Targets)
	sort.Slice(dataset.Discoveries, func(i, j int) bool { return dataset.Discoveries[i].URL < dataset.Discoveries[j].URL })
	sort.Slice(dataset.BruteObservations, func(i, j int) bool { return dataset.BruteObservations[i].URL < dataset.BruteObservations[j].URL })
	sort.Slice(dataset.Operations, func(i, j int) bool {
		return dataset.Operations[i].Source+dataset.Operations[i].Method+dataset.Operations[i].Target < dataset.Operations[j].Source+dataset.Operations[j].Method+dataset.Operations[j].Target
	})
	sort.Slice(dataset.Failures, func(i, j int) bool {
		return dataset.Failures[i].Source+dataset.Failures[i].Error < dataset.Failures[j].Source+dataset.Failures[j].Error
	})
	unique := len(dataset.Targets) + len(dataset.Discoveries) + len(dataset.BruteObservations) + len(dataset.Operations) + len(dataset.Failures)
	for index, finding := range storedFindings {
		var evidence struct {
			Summary string   `json:"summary"`
			OWASP   []string `json:"owasp"`
		}
		if err := decodeMetadata(finding.Evidence, &evidence); err != nil {
			return Dataset{}, fmt.Errorf("decode stored finding %d: %w", index+1, err)
		}
		imported := ImportedFinding{
			Severity: finding.Severity, Category: finding.Category, Title: finding.Title,
			Method: finding.Method, URL: finding.URL, Evidence: evidence.Summary, OWASP: evidence.OWASP,
		}
		importedFindings[importedFindingKey(imported)] = imported
	}
	for _, finding := range importedFindings {
		dataset.ImportedFindings = append(dataset.ImportedFindings, finding)
	}
	sort.Slice(dataset.ImportedFindings, func(i, j int) bool {
		return importedFindingKey(dataset.ImportedFindings[i]) < importedFindingKey(dataset.ImportedFindings[j])
	})
	unique += len(dataset.ImportedFindings)
	dataset.RawRecords += len(storedFindings)
	dataset.DuplicateRecords = max(0, dataset.RawRecords-unique)
	return dataset, nil
}

func MergeDatasets(datasets ...Dataset) Dataset {
	var merged Dataset
	targets := make(map[string]struct{})
	discoveries := make(map[string]Discovery)
	interesting := make(map[string]BruteObservation)
	operations := make(map[string]Operation)
	failures := make(map[string]Failure)
	importedFindings := make(map[string]ImportedFinding)
	for _, dataset := range datasets {
		merged.Files = append(merged.Files, dataset.Files...)
		merged.IgnoredFiles = append(merged.IgnoredFiles, dataset.IgnoredFiles...)
		merged.RawRecords += dataset.RawRecords
		merged.BruteURLsTested += dataset.BruteURLsTested
		merged.BruteRequestErrors += dataset.BruteRequestErrors
		merged.BruteFalsePositivesFiltered += dataset.BruteFalsePositivesFiltered
		merged.TransportLimitedTargets += dataset.TransportLimitedTargets
		merged.WAFChallengedTargets += dataset.WAFChallengedTargets
		merged.WAFChallengeResponses += dataset.WAFChallengeResponses
		merged.WAFChallengeLimitedTargets += dataset.WAFChallengeLimitedTargets
		merged.BruteReferencesRejected += dataset.BruteReferencesRejected
		merged.BruteReferencesSkipped += dataset.BruteReferencesSkipped
		merged.RateLimitedTargets += dataset.RateLimitedTargets
		merged.UnavailableLimitedTargets += dataset.UnavailableLimitedTargets
		for _, value := range dataset.ImportedFindings {
			importedFindings[importedFindingKey(value)] = value
		}
		for _, value := range dataset.Targets {
			targets[value] = struct{}{}
		}
		for _, value := range dataset.Discoveries {
			discoveries[value.URL] = value
		}
		for _, value := range dataset.BruteObservations {
			interesting[value.URL+"\x00"+strconv.Itoa(value.Status)] = value
		}
		for _, value := range dataset.Operations {
			key := strings.Join([]string{
				value.Source, value.Method, value.URL, value.Target, strconv.Itoa(value.Status),
				value.BaselineURL, value.Case, value.Identity,
			}, "\x00")
			operations[key] = value
		}
		for _, value := range dataset.Failures {
			failures[value.Source+"\x00"+value.Error] = value
		}
	}
	for value := range targets {
		merged.Targets = append(merged.Targets, value)
	}
	for _, value := range discoveries {
		merged.Discoveries = append(merged.Discoveries, value)
	}
	for _, value := range interesting {
		merged.BruteObservations = append(merged.BruteObservations, value)
	}
	for _, value := range operations {
		merged.Operations = append(merged.Operations, value)
	}
	for _, value := range failures {
		merged.Failures = append(merged.Failures, value)
	}
	for _, value := range importedFindings {
		merged.ImportedFindings = append(merged.ImportedFindings, value)
	}
	sort.Strings(merged.Targets)
	sort.Strings(merged.IgnoredFiles)
	sort.Slice(merged.Discoveries, func(i, j int) bool { return merged.Discoveries[i].URL < merged.Discoveries[j].URL })
	sort.Slice(merged.BruteObservations, func(i, j int) bool { return merged.BruteObservations[i].URL < merged.BruteObservations[j].URL })
	sort.Slice(merged.Operations, func(i, j int) bool {
		return merged.Operations[i].Source+merged.Operations[i].Method+merged.Operations[i].Target < merged.Operations[j].Source+merged.Operations[j].Method+merged.Operations[j].Target
	})
	sort.Slice(merged.ImportedFindings, func(i, j int) bool {
		return importedFindingKey(merged.ImportedFindings[i]) < importedFindingKey(merged.ImportedFindings[j])
	})
	unique := len(merged.Targets) + len(merged.Discoveries) + len(merged.BruteObservations) + len(merged.Operations) + len(merged.Failures) + len(merged.ImportedFindings)
	merged.DuplicateRecords = max(0, merged.RawRecords-unique)
	return merged
}

func importedFindingKey(value ImportedFinding) string {
	return strings.Join([]string{value.Severity, value.Category, value.Title, value.Method, value.URL, value.Evidence, strings.Join(value.OWASP, ",")}, "\x00")
}

func observationMetadata(value any) (map[string]any, error) {
	result := make(map[string]any)
	if err := decodeMetadata(value, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func decodeMetadata(value any, destination any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if raw, ok := value.(json.RawMessage); ok {
		data = raw
	}
	return json.Unmarshal(data, destination)
}

func stringMetadata(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}
