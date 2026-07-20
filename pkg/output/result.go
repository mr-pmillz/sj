package output

type Result struct {
	Source            string `json:"source,omitempty"`
	Method            string `json:"method"`
	Status            int    `json:"status"`
	Target            string `json:"target"`
	URL               string `json:"url,omitempty"`
	ContentType       string `json:"content_type,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	ResponseBody      string `json:"response_body,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
}

type VerboseResult struct {
	Source            string `json:"source,omitempty"`
	Method            string `json:"method"`
	Preview           string `json:"preview"`
	Status            int    `json:"status"`
	Target            string `json:"target"`
	URL               string `json:"url,omitempty"`
	ContentType       string `json:"content_type,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	ResponseBody      string `json:"response_body,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
	Curl              string `json:"curl"`
}
