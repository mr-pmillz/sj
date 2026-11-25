package contract

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Class   string        `xml:"classname,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Skipped *junitSkipped `xml:"skipped,omitempty"`
	Output  string        `xml:"system-out"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value int    `xml:"value,attr"`
}

// Verify checks that a report is complete and that its totals, coverage and
// findings all follow from its case results. Every exporter calls it, so a
// partial or edited file cannot pass CI.
func (r Report) Verify() error {
	report := r
	if len(report.Cases) == 0 || (report.Planned != 0 && report.Planned != len(report.Cases)) {
		return errors.New("missing or incomplete contract case results")
	}
	counts := Report{observed: make(map[string]bool), matched: make(map[string]bool)}
	names := make(map[string]bool)
	for _, result := range report.Cases {
		if result.Name == "" || result.Method == "" || result.Path == "" || names[result.Name] {
			return errors.New("invalid or duplicate case identity in contract report")
		}
		unsent := result.Status == 0
		if unsent && ((len(result.Problems) == 0) == (result.Skipped == "") || len(result.Findings) != 0 || result.MatchedResponse != "" || result.Credentialed) {
			return errors.New("contract case without an HTTP response has inconsistent outcomes")
		}
		if !unsent && (result.Skipped != "" || result.Status < 100 || result.Status > 599) {
			return errors.New("invalid HTTP status in contract report")
		}
		switch result.MatchedResponse {
		case "", "default", strconv.Itoa(result.Status), strconv.Itoa(result.Status/100) + "XX":
		default:
			return errors.New("matched response does not cover the observed status")
		}
		names[result.Name] = true
		counts.tally(result)
	}
	c := report.Coverage
	if counts.Failed != report.Failed || counts.Passed != report.Passed ||
		counts.Skipped != report.Skipped || counts.Inconclusive != report.Inconclusive ||
		c.ExercisedOperations != counts.Coverage.ExercisedOperations || c.MatchedResponses != counts.Coverage.MatchedResponses ||
		c.DocumentedOperations < c.ExercisedOperations || c.DocumentedResponses < c.MatchedResponses {
		return errors.New("contract totals disagree with case results")
	}
	return checkFindings(report)
}

// WriteJUnit exports the exact case outcomes from a contract report.
func WriteJUnit(out io.Writer, report Report) error {
	if err := report.Verify(); err != nil {
		return err
	}
	suite := struct {
		XMLName    xml.Name        `xml:"testsuite"`
		Name       string          `xml:"name,attr"`
		Tests      int             `xml:"tests,attr"`
		Failures   int             `xml:"failures,attr"`
		Skipped    int             `xml:"skipped,attr,omitempty"`
		Properties []junitProperty `xml:"properties>property"`
		Cases      []junitCase     `xml:"testcase"`
	}{
		Name: "sj contract", Tests: len(report.Cases), Failures: report.Failed, Skipped: report.Skipped + report.Inconclusive,
		Properties: []junitProperty{
			{"documentedOperations", report.Coverage.DocumentedOperations},
			{"exercisedOperations", report.Coverage.ExercisedOperations},
			{"documentedResponses", report.Coverage.DocumentedResponses},
			{"matchedResponses", report.Coverage.MatchedResponses},
		},
	}
	for _, result := range report.Cases {
		row := junitCase{Name: result.Name, Class: result.Method + " " + result.Path,
			Output: fmt.Sprintf("HTTP status %d, credentialed %t", result.Status, result.Credentialed)}
		failures := slices.Concat(result.Problems, result.Findings)
		switch {
		case result.Skipped != "":
			row.Skipped = &junitSkipped{Message: result.Skipped}
		case len(failures) != 0:
			row.Failure = &junitFailure{Message: strings.Join(failures, ", "), Text: strings.Join(failures, "\n")}
		case result.Inconclusive != "":
			row.Skipped = &junitSkipped{Message: result.Inconclusive}
		}
		suite.Cases = append(suite.Cases, row)
	}
	encoder := xml.NewEncoder(out)
	encoder.Indent("", "  ")
	return encoder.Encode(suite)
}

// checkFindings verifies that every finding is backed by case results that
// raised it, and that no case signal is missing from the findings.
func checkFindings(report Report) error {
	signals := make(map[string]bool)
	for _, result := range report.Cases {
		if result.Skipped != "" || result.Cleanup {
			continue
		}
		for _, signal := range slices.Concat(result.Findings, result.Problems) {
			kind, _, _ := strings.Cut(signal, " ")
			if _, known := findingClasses[kind]; known {
				signals[kind+" "+result.Name] = true
			}
		}
	}
	covered := make(map[string]bool)
	absorbed := make(map[string]bool)
	for _, finding := range report.Findings {
		class, known := findingClasses[finding.Kind]
		if !known || len(finding.Cases) == 0 || class.category != finding.Category || severityRank[finding.Severity] == 0 && finding.Severity != "critical" {
			return errors.New("finding has an unknown kind, category or severity, or no supporting case")
		}
		for _, name := range finding.Cases {
			// This kind is derived from a pair of cases rather than one signal.
			if finding.Kind != FindingUndeclaredSecurity && !signals[finding.Kind+" "+name] {
				return errors.New("finding names a case that did not raise it")
			}
			covered[finding.Kind+" "+name] = true
		}
		if finding.Kind == FindingAuthNotEnforced {
			absorbed[finding.Operation()] = true
		}
	}
	for _, result := range report.Cases {
		for _, signal := range slices.Concat(result.Findings, result.Problems) {
			kind, _, _ := strings.Cut(signal, " ")
			key := kind + " " + result.Name
			if !signals[key] || covered[key] {
				continue
			}
			// A made-up credential that works is folded into the missing-enforcement finding.
			if kind == FindingInvalidCredential && absorbed[result.Method+" "+result.Path] {
				continue
			}
			return errors.New("a case signal is missing from the findings")
		}
	}
	return nil
}
