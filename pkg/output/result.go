package output

type Result struct {
	Source string `json:"source,omitempty"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Target string `json:"target"`
}

type VerboseResult struct {
	Source  string `json:"source,omitempty"`
	Method  string `json:"method"`
	Preview string `json:"preview"`
	Status  int    `json:"status"`
	Target  string `json:"target"`
	Curl    string `json:"curl"`
}
