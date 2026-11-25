package contract

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestWriteJUnitChecksCountsAndEscapesCaseText(t *testing.T) {
	report := Report{
		Planned: 1, Failed: 1, Cases: []Result{{Name: `caller <A> & "B"`, Method: "GET", Path: "/me", Status: 403,
			MatchedResponse: "4XX", Credentialed: true, Problems: []string{"unexpected_status"}}},
		Coverage: Coverage{DocumentedOperations: 1, ExercisedOperations: 1, DocumentedResponses: 2, MatchedResponses: 1},
	}
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, report); err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Row struct {
			Name string `xml:"name,attr"`
			Text string `xml:"failure"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &suite); err != nil || suite.Row.Name != report.Cases[0].Name || suite.Row.Text != "unexpected_status" {
		t.Fatalf("incorrect JUnit case %v, error %v", suite, err)
	}
	for _, change := range []func(*Report){
		func(r *Report) { r.Planned++ },
		func(r *Report) { r.Passed++ },
		func(r *Report) { r.Coverage.MatchedResponses = 2 },
		func(r *Report) { r.Cases = nil },
		func(r *Report) { r.Cases = append(r.Cases, r.Cases[0]) },
	} {
		r := report
		change(&r)
		var out strings.Builder
		if err := WriteJUnit(&out, r); err == nil || out.Len() != 0 {
			t.Fatal("inconsistent report exported")
		}
	}
}
