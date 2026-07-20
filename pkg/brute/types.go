package brute

import "github.com/getkin/kin-openapi/openapi3"

// SpecResult holds metadata about a discovered OpenAPI/Swagger specification.
type SpecResult struct {
	URL            string `json:"url"`
	ContentType    string `json:"content_type"`
	OpenAPIVersion string `json:"openapi_version"`
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
}

// Interesting holds metadata about a URL that returned a notable response.
type Interesting struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
}

// Report is the per-target brute-force scan result.
type Report struct {
	Target      string        `json:"target"`
	SpecsFound  []SpecResult  `json:"specs_found"`
	Interesting []Interesting `json:"interesting_urls,omitempty"`
	Summary     Summary       `json:"summary"`
}

// Summary counts high-level statistics for a brute-force run.
type Summary struct {
	URLsTested                 int  `json:"urls_tested"`
	SpecsFoundCount            int  `json:"specs_found_count"`
	Responses2xx               int  `json:"responses_2xx"`
	Responses3xx               int  `json:"responses_3xx"`
	Responses4xx               int  `json:"responses_4xx"`
	Responses5xx               int  `json:"responses_5xx"`
	Errors                     int  `json:"errors"`
	TransportErrorLimitReached bool `json:"transport_error_limit_reached,omitempty"`
	WildcardResponseDetected   bool `json:"wildcard_response_detected,omitempty"`
	FalsePositivesFiltered     int  `json:"false_positives_filtered,omitempty"`
}

// match is an internal type used while scanning for spec files.
type match struct {
	url         string
	contentType string
	spec        *openapi3.T
	version     string
	title       string
	description string
}
