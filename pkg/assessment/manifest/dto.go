package manifest

type document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   metadata `yaml:"metadata"`
	Spec       spec     `yaml:"spec"`
}

type metadata struct {
	Name string `yaml:"name"`
}

type spec struct {
	Origins      []string      `yaml:"origins"`
	Inputs       []inputSource `yaml:"inputs"`
	Window       window        `yaml:"window"`
	Transport    transport     `yaml:"transport"`
	Identities   []identity    `yaml:"identities"`
	OwnedObjects []ownedObject `yaml:"ownedObjects"`
	Modules      []module      `yaml:"modules"`
	Budgets      budgets       `yaml:"budgets"`
	Evidence     evidence      `yaml:"evidence"`
	Workflows    []workflow    `yaml:"workflows"`
}

type inputSource struct {
	Name       string   `yaml:"name"`
	Kind       string   `yaml:"kind"`
	Path       string   `yaml:"path"`
	URL        string   `yaml:"url"`
	RunID      string   `yaml:"runId"`
	BaseURL    string   `yaml:"baseURL"`
	Operations []string `yaml:"operations"`
	Modules    []string `yaml:"modules"`
}

type window struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

type transport struct {
	Proxy     proxy     `yaml:"proxy"`
	TLS       tls       `yaml:"tls"`
	Redirects redirects `yaml:"redirects"`
}

type proxy struct {
	Required bool   `yaml:"required"`
	URL      string `yaml:"url"`
}

type tls struct {
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	Justification      string `yaml:"justification"`
}

type redirects struct {
	SameOriginOnly bool `yaml:"sameOriginOnly"`
	Max            int  `yaml:"max"`
}

type identity struct {
	Name    string            `yaml:"name"`
	Role    string            `yaml:"role"`
	Tenant  string            `yaml:"tenant"`
	Headers map[string]string `yaml:"headers"`
	Cookies map[string]string `yaml:"cookies"`
}

type ownedObject struct {
	Name             string            `yaml:"name"`
	Type             string            `yaml:"type"`
	Identifier       string            `yaml:"identifier"`
	Owner            string            `yaml:"owner"`
	Tenant           string            `yaml:"tenant"`
	Provenance       string            `yaml:"provenance"`
	Stable           bool              `yaml:"stable"`
	Disposable       bool              `yaml:"disposable"`
	RollbackWorkflow string            `yaml:"rollbackWorkflow"`
	ExpectedAccess   map[string]string `yaml:"expectedAccess"`
}

type module struct {
	Name        string `yaml:"name"`
	Enabled     bool   `yaml:"enabled"`
	SafetyClass string `yaml:"safetyClass"`
}

type budgetLimit struct {
	MaxRequests       int64   `yaml:"maxRequests"`
	MaxRequestBytes   int64   `yaml:"maxRequestBytes"`
	MaxResponseBytes  int64   `yaml:"maxResponseBytes"`
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
}

type budgets struct {
	Global      budgetLimit            `yaml:"global"`
	PerOrigin   map[string]budgetLimit `yaml:"perOrigin"`
	PerModule   map[string]budgetLimit `yaml:"perModule"`
	PerIdentity map[string]budgetLimit `yaml:"perIdentity"`
}

type evidence struct {
	StoreResponseBodies     bool   `yaml:"storeResponseBodies"`
	EncryptionKey           string `yaml:"encryptionKey"`
	MaxArtifactBytes        int64  `yaml:"maxArtifactBytes"`
	Retention               string `yaml:"retention"`
	IncludeSensitiveExports bool   `yaml:"includeSensitiveExports"`
}

type workflow struct {
	Name        string         `yaml:"name"`
	SafetyClass string         `yaml:"safetyClass"`
	Fixture     string         `yaml:"fixture"`
	Steps       []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name        string `yaml:"name"`
	Purpose     string `yaml:"purpose"`
	OperationID string `yaml:"operationId"`
	Identity    string `yaml:"identity"`
	Method      string `yaml:"method"`
}
