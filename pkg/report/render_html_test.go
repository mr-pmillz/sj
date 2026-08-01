package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
)

func TestHTMLReportIncludesSelfContainedFindingTableControls(t *testing.T) {
	report := Report{
		Title:       "SJ authorized API assessment",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Findings: []Finding{
			{ID: "F-HIGH", Severity: SeverityHigh, Title: "Persistent anonymous write", Count: 1},
			{ID: "F-MED", Severity: SeverityMedium, Title: "Verbose database error", Count: 2},
		},
	}

	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, expected := range []string{
		`id="theme-toggle"`, `id="finding-search"`, `id="severity-filter"`,
		`id="findings-table"`, `data-sort="severity"`, `aria-sort="descending"`,
		`id="page-size"`, `id="pagination"`, `data-finding-id="F-HIGH"`,
		`class="finding-detail"`, `data-action="toggle-finding"`,
		`severityRank`, `firstDirection`,
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("HTML report omitted %q", expected)
		}
	}
	for _, forbidden := range []string{"cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("HTML report depends on external asset %q", forbidden)
		}
	}
	if !strings.Contains(rendered, `script-src 'unsafe-inline'`) {
		t.Fatalf("CSP does not permit the report's self-contained controller: %s", rendered[:min(len(rendered), 800)])
	}
}

func TestHTMLReportRendersEveryFullEscapedHTTPExchange(t *testing.T) {
	report := Report{
		Title:       "Evidence",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Findings: []Finding{{
			ID: "API5-PERSISTENT-WRITE", Severity: SeverityHigh, Title: "Persistent write",
			Evidence: []Evidence{
				{
					Source: "run-one", Method: "POST", Status: 201,
					URL: "https://qa.example/entities", ContentType: "application/json; charset=utf-8",
					RequestBody:  `{"entity_id":"<script>alert(1)</script>"}`,
					ResponseBody: `{"entity_id":"testvalue","created":true}`,
				},
				{
					Source: "run-two", Method: "GET", Status: 200,
					URL: "https://qa.example/entities/testvalue", ContentType: "application/json",
					ResponseBody: `{"entity_id":"testvalue"}`, ResponseTruncated: true,
				},
			},
		}},
	}

	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, expected := range []string{
		"POST https://qa.example/entities HTTP/1.1",
		"GET https://qa.example/entities/testvalue HTTP/1.1",
		"HTTP/1.1 201",
		"HTTP/1.1 200",
		"Content-Type: application/json; charset=utf-8",
		`{&#34;entity_id&#34;:&#34;&lt;script&gt;alert(1)&lt;/script&gt;&#34;}`,
		`{&#34;entity_id&#34;:&#34;testvalue&#34;,&#34;created&#34;:true}`,
		"Captured response was truncated",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("HTML report omitted exchange content %q", expected)
		}
	}
	if strings.Contains(rendered, `<script>alert(1)</script>`) {
		t.Fatal("unescaped retained evidence became executable HTML")
	}
	if got := strings.Count(rendered, `class="exchange"`); got != 2 {
		t.Fatalf("rendered %d evidence exchanges, want 2", got)
	}
}

func TestHTMLReportUsesAccessibleSortableColumnHeaders(t *testing.T) {
	report := Report{Title: "Sort", GeneratedAt: time.Unix(0, 0).UTC(), Findings: []Finding{{
		ID: "ONE", Severity: SeverityHigh, Title: "Finding", Count: 1, WeightedPoints: 8,
	}}}
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, column := range []string{"severity", "id", "title", "affected", "points"} {
		if !strings.Contains(rendered, `data-sort="`+column+`"`) {
			t.Errorf("column %q is not sortable", column)
		}
	}
	if !strings.Contains(rendered, `sortColumn='severity',sortDirection='desc'`) {
		t.Fatal("severity sort state does not match its initial descending presentation")
	}
	if !strings.Contains(rendered, `return current==='desc'?'asc':'desc'`) {
		t.Fatal("repeated column clicks do not toggle their sort direction")
	}
}

func TestHTMLReportSpecificationHostStatisticsAreSortable(t *testing.T) {
	report := Report{
		Title:       "Host sorting",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Hosts: []HostMetric{
			{Host: "z.example", Operations: 3, Successes: 2, Challenges: 1, SuccessRate: 66.67},
			{Host: "a.example", Operations: 8, Successes: 7, ClientErrors: 1, SuccessRate: 87.5},
		},
	}
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	if !strings.Contains(rendered, `id="host-statistics-table"`) {
		t.Fatal("specification-host statistics table has no stable sortable-table identifier")
	}
	for _, column := range []string{"host", "operations", "successes", "challenges", "clientErrors", "serverErrors", "successRate"} {
		if !strings.Contains(rendered, `data-host-sort="`+column+`"`) {
			t.Errorf("specification-host column %q is not sortable", column)
		}
	}
	for _, expected := range []string{
		`data-host="z.example"`, `data-operations="3"`, `data-success-rate="66.67"`,
		`hostSortDirection`, `hostRows.sort`, `localeCompare`,
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("sortable specification-host table omitted %q", expected)
		}
	}
}

func TestHTMLReportIncludesRetainedEvidenceProvenance(t *testing.T) {
	report := Report{Title: "Provenance", GeneratedAt: time.Unix(0, 0).UTC(), Findings: []Finding{{
		ID: "PROOF", Severity: SeverityMedium, Title: "Proof", Evidence: []Evidence{{
			RunID: "e670c04e", ObservationID: 2464, ObservedAt: time.Date(2026, 7, 31, 4, 3, 2, 0, time.UTC),
			AuthContext: "anonymous", Identity: "unrecorded", Source: "stored-results", Method: "POST", Status: 201,
			URL: "https://qa.example/entities",
		}},
	}}}
	var output bytes.Buffer
	if err := Write(report, "html", &output, config.ColorNever); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Run: e670c04e", "Observation: 2464", "Captured: 2026-07-31 04:03:02 UTC",
		"Auth context: anonymous", "Identity: unrecorded",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("HTML report omitted provenance %q", expected)
		}
	}
}
