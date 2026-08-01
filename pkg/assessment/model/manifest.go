package model

import "time"

type Origin struct{ value string }

func NewOrigin(value string) Origin { return Origin{value: value} }
func (o Origin) String() string     { return o.value }

type TimeWindow struct {
	start time.Time
	end   time.Time
}

func NewTimeWindow(start, end time.Time) TimeWindow { return TimeWindow{start: start, end: end} }
func (w TimeWindow) Start() time.Time               { return w.start }
func (w TimeWindow) End() time.Time                 { return w.end }

type ProxyPolicy struct {
	required bool
	url      string
}

func NewProxyPolicy(required bool, url string) ProxyPolicy {
	return ProxyPolicy{required: required, url: url}
}
func (p ProxyPolicy) Required() bool { return p.required }
func (p ProxyPolicy) URL() string    { return p.url }

type TLSPolicy struct {
	insecureSkipVerify bool
	justification      string
}

func NewTLSPolicy(insecureSkipVerify bool, justification string) TLSPolicy {
	return TLSPolicy{insecureSkipVerify: insecureSkipVerify, justification: justification}
}
func (p TLSPolicy) InsecureSkipVerify() bool { return p.insecureSkipVerify }
func (p TLSPolicy) Justification() string    { return p.justification }

type RedirectPolicy struct {
	sameOriginOnly bool
	max            int
}

func NewRedirectPolicy(sameOriginOnly bool, max int) RedirectPolicy {
	return RedirectPolicy{sameOriginOnly: sameOriginOnly, max: max}
}
func (p RedirectPolicy) SameOriginOnly() bool { return p.sameOriginOnly }
func (p RedirectPolicy) Max() int             { return p.max }

type TransportPolicy struct {
	proxy     ProxyPolicy
	tls       TLSPolicy
	redirects RedirectPolicy
}

func NewTransportPolicy(proxy ProxyPolicy, tls TLSPolicy, redirects RedirectPolicy) TransportPolicy {
	return TransportPolicy{proxy: proxy, tls: tls, redirects: redirects}
}
func (p TransportPolicy) Proxy() ProxyPolicy        { return p.proxy }
func (p TransportPolicy) TLS() TLSPolicy            { return p.tls }
func (p TransportPolicy) Redirects() RedirectPolicy { return p.redirects }

type Identity struct {
	name    string
	role    string
	tenant  string
	headers map[string]SecretRef
	cookies map[string]SecretRef
}

func NewIdentity(name, role, tenant string, headers, cookies map[string]SecretRef) Identity {
	return Identity{name: name, role: role, tenant: tenant, headers: cloneMap(headers), cookies: cloneMap(cookies)}
}
func (i Identity) Name() string                  { return i.name }
func (i Identity) Role() string                  { return i.role }
func (i Identity) Tenant() string                { return i.tenant }
func (i Identity) Headers() map[string]SecretRef { return cloneMap(i.headers) }
func (i Identity) Cookies() map[string]SecretRef { return cloneMap(i.cookies) }
func (i Identity) Clone() Identity {
	return NewIdentity(i.name, i.role, i.tenant, i.headers, i.cookies)
}

type OwnedObject struct {
	name             string
	typeName         string
	identifier       string
	owner            string
	tenant           string
	provenance       string
	stable           bool
	disposable       bool
	rollbackWorkflow string
	expectedAccess   map[string]ExpectedAccess
}

func NewOwnedObject(name, typeName, identifier, owner, tenant, provenance string, stable bool, rollbackWorkflow string, expected map[string]ExpectedAccess) OwnedObject {
	return OwnedObject{name: name, typeName: typeName, identifier: identifier, owner: owner, tenant: tenant, provenance: provenance, stable: stable, rollbackWorkflow: rollbackWorkflow, expectedAccess: cloneMap(expected)}
}

func NewDisposableOwnedObject(name, typeName, identifier, owner, tenant, provenance string, stable bool, rollbackWorkflow string, expected map[string]ExpectedAccess) OwnedObject {
	return OwnedObject{name: name, typeName: typeName, identifier: identifier, owner: owner, tenant: tenant, provenance: provenance, stable: stable, disposable: true, rollbackWorkflow: rollbackWorkflow, expectedAccess: cloneMap(expected)}
}
func (o OwnedObject) Name() string                              { return o.name }
func (o OwnedObject) Type() string                              { return o.typeName }
func (o OwnedObject) Identifier() string                        { return o.identifier }
func (o OwnedObject) Owner() string                             { return o.owner }
func (o OwnedObject) Tenant() string                            { return o.tenant }
func (o OwnedObject) Provenance() string                        { return o.provenance }
func (o OwnedObject) Stable() bool                              { return o.stable }
func (o OwnedObject) Disposable() bool                          { return o.disposable }
func (o OwnedObject) RollbackWorkflow() string                  { return o.rollbackWorkflow }
func (o OwnedObject) ExpectedAccess() map[string]ExpectedAccess { return cloneMap(o.expectedAccess) }
func (o OwnedObject) Clone() OwnedObject {
	if o.disposable {
		return NewDisposableOwnedObject(o.name, o.typeName, o.identifier, o.owner, o.tenant, o.provenance, o.stable, o.rollbackWorkflow, o.expectedAccess)
	}
	return NewOwnedObject(o.name, o.typeName, o.identifier, o.owner, o.tenant, o.provenance, o.stable, o.rollbackWorkflow, o.expectedAccess)
}

type ModuleConfig struct {
	name        string
	enabled     bool
	safetyClass SafetyClass
}

func NewModuleConfig(name string, enabled bool, safetyClass SafetyClass) ModuleConfig {
	return ModuleConfig{name: name, enabled: enabled, safetyClass: safetyClass}
}
func (m ModuleConfig) Name() string             { return m.name }
func (m ModuleConfig) Enabled() bool            { return m.enabled }
func (m ModuleConfig) SafetyClass() SafetyClass { return m.safetyClass }
func (m ModuleConfig) IsStateChanging() bool    { return m.enabled && m.safetyClass.IsStateChanging() }

type BudgetLimit struct {
	maxRequests       int64
	maxRequestBytes   int64
	maxResponseBytes  int64
	requestsPerSecond float64
}

func NewBudgetLimit(maxRequests, maxRequestBytes, maxResponseBytes int64, requestsPerSecond float64) BudgetLimit {
	return BudgetLimit{maxRequests: maxRequests, maxRequestBytes: maxRequestBytes, maxResponseBytes: maxResponseBytes, requestsPerSecond: requestsPerSecond}
}
func (b BudgetLimit) MaxRequests() int64         { return b.maxRequests }
func (b BudgetLimit) MaxRequestBytes() int64     { return b.maxRequestBytes }
func (b BudgetLimit) MaxResponseBytes() int64    { return b.maxResponseBytes }
func (b BudgetLimit) RequestsPerSecond() float64 { return b.requestsPerSecond }

type Budgets struct {
	global      BudgetLimit
	perOrigin   map[string]BudgetLimit
	perModule   map[string]BudgetLimit
	perIdentity map[string]BudgetLimit
}

func NewBudgets(global BudgetLimit, perOrigin, perModule, perIdentity map[string]BudgetLimit) Budgets {
	return Budgets{global: global, perOrigin: cloneMap(perOrigin), perModule: cloneMap(perModule), perIdentity: cloneMap(perIdentity)}
}
func (b Budgets) Global() BudgetLimit                 { return b.global }
func (b Budgets) PerOrigin() map[string]BudgetLimit   { return cloneMap(b.perOrigin) }
func (b Budgets) PerModule() map[string]BudgetLimit   { return cloneMap(b.perModule) }
func (b Budgets) PerIdentity() map[string]BudgetLimit { return cloneMap(b.perIdentity) }

type EvidenceConfig struct {
	storeResponseBodies     bool
	encryptionKey           SecretRef
	maxArtifactBytes        int64
	retention               time.Duration
	includeSensitiveExports bool
}

func NewEvidenceConfig(storeBodies bool, key SecretRef, maxArtifactBytes int64, retention time.Duration, includeSensitiveExports bool) EvidenceConfig {
	return EvidenceConfig{storeResponseBodies: storeBodies, encryptionKey: key, maxArtifactBytes: maxArtifactBytes, retention: retention, includeSensitiveExports: includeSensitiveExports}
}
func (e EvidenceConfig) StoreResponseBodies() bool     { return e.storeResponseBodies }
func (e EvidenceConfig) EncryptionKey() SecretRef      { return e.encryptionKey }
func (e EvidenceConfig) MaxArtifactBytes() int64       { return e.maxArtifactBytes }
func (e EvidenceConfig) Retention() time.Duration      { return e.retention }
func (e EvidenceConfig) IncludeSensitiveExports() bool { return e.includeSensitiveExports }

type WorkflowPurpose uint8

const (
	WorkflowPurposeUnknown WorkflowPurpose = iota
	WorkflowPurposeMutation
	WorkflowPurposeReadback
	WorkflowPurposeRollback
)

func ParseWorkflowPurpose(value string) (WorkflowPurpose, bool) {
	switch value {
	case "mutation":
		return WorkflowPurposeMutation, true
	case "readback":
		return WorkflowPurposeReadback, true
	case "rollback":
		return WorkflowPurposeRollback, true
	default:
		return WorkflowPurposeUnknown, false
	}
}

func (p WorkflowPurpose) String() string {
	switch p {
	case WorkflowPurposeMutation:
		return "mutation"
	case WorkflowPurposeReadback:
		return "readback"
	case WorkflowPurposeRollback:
		return "rollback"
	default:
		return "unknown"
	}
}

type WorkflowStep struct {
	name        string
	purpose     WorkflowPurpose
	operationID string
	identity    string
	method      string
}

func NewWorkflowStep(name string, purpose WorkflowPurpose, operationID, identity, method string) WorkflowStep {
	return WorkflowStep{name: name, purpose: purpose, operationID: operationID, identity: identity, method: method}
}
func (s WorkflowStep) Name() string             { return s.name }
func (s WorkflowStep) Purpose() WorkflowPurpose { return s.purpose }
func (s WorkflowStep) OperationID() string      { return s.operationID }
func (s WorkflowStep) Identity() string         { return s.identity }
func (s WorkflowStep) Method() string           { return s.method }

type Workflow struct {
	name        string
	safetyClass SafetyClass
	fixture     string
	steps       []WorkflowStep
}

func NewWorkflow(name string, safetyClass SafetyClass, fixture string, steps []WorkflowStep) Workflow {
	return Workflow{name: name, safetyClass: safetyClass, fixture: fixture, steps: cloneSlice(steps)}
}
func (w Workflow) Name() string             { return w.name }
func (w Workflow) SafetyClass() SafetyClass { return w.safetyClass }
func (w Workflow) Fixture() string          { return w.fixture }
func (w Workflow) Steps() []WorkflowStep    { return cloneSlice(w.steps) }
func (w Workflow) Clone() Workflow          { return NewWorkflow(w.name, w.safetyClass, w.fixture, w.steps) }

type InputKind uint8

const (
	InputKindUnknown InputKind = iota
	InputKindOpenAPI
	InputKindSJResults
)

func ParseInputKind(value string) (InputKind, bool) {
	switch value {
	case "openapi":
		return InputKindOpenAPI, true
	case "sj-results":
		return InputKindSJResults, true
	default:
		return InputKindUnknown, false
	}
}

func (k InputKind) String() string {
	switch k {
	case InputKindOpenAPI:
		return "openapi"
	case InputKindSJResults:
		return "sj-results"
	default:
		return "unknown"
	}
}

type InputSource struct {
	name       string
	kind       InputKind
	path       string
	url        string
	runID      string
	baseURL    string
	operations []string
	modules    []string
}

func NewInputSource(name string, kind InputKind, path, sourceURL, runID, baseURL string, operations, modules []string) InputSource {
	return InputSource{name: name, kind: kind, path: path, url: sourceURL, runID: runID, baseURL: baseURL, operations: cloneSlice(operations), modules: cloneSlice(modules)}
}
func (s InputSource) Name() string         { return s.name }
func (s InputSource) Kind() InputKind      { return s.kind }
func (s InputSource) Path() string         { return s.path }
func (s InputSource) URL() string          { return s.url }
func (s InputSource) RunID() string        { return s.runID }
func (s InputSource) BaseURL() string      { return s.baseURL }
func (s InputSource) Operations() []string { return cloneSlice(s.operations) }
func (s InputSource) Modules() []string    { return cloneSlice(s.modules) }
func (s InputSource) Clone() InputSource {
	return NewInputSource(s.name, s.kind, s.path, s.url, s.runID, s.baseURL, s.operations, s.modules)
}

type ManifestParams struct {
	APIVersion string
	Kind       string
	Name       string
	Origins    []Origin
	Inputs     []InputSource
	Window     TimeWindow
	Transport  TransportPolicy
	Identities []Identity
	Objects    []OwnedObject
	Modules    []ModuleConfig
	Budgets    Budgets
	Evidence   EvidenceConfig
	Workflows  []Workflow
}

type Manifest struct {
	apiVersion string
	kind       string
	name       string
	origins    []Origin
	inputs     []InputSource
	window     TimeWindow
	transport  TransportPolicy
	identities []Identity
	objects    []OwnedObject
	modules    []ModuleConfig
	budgets    Budgets
	evidence   EvidenceConfig
	workflows  []Workflow
}

func NewManifest(p ManifestParams) Manifest {
	identities := make([]Identity, len(p.Identities))
	for index, identity := range p.Identities {
		identities[index] = identity.Clone()
	}
	objects := make([]OwnedObject, len(p.Objects))
	for index, object := range p.Objects {
		objects[index] = object.Clone()
	}
	inputs := make([]InputSource, len(p.Inputs))
	for index, input := range p.Inputs {
		inputs[index] = input.Clone()
	}
	workflows := make([]Workflow, len(p.Workflows))
	for index, workflow := range p.Workflows {
		workflows[index] = workflow.Clone()
	}
	return Manifest{apiVersion: p.APIVersion, kind: p.Kind, name: p.Name, origins: cloneSlice(p.Origins), inputs: inputs, window: p.Window, transport: p.Transport, identities: identities, objects: objects, modules: cloneSlice(p.Modules), budgets: NewBudgets(p.Budgets.global, p.Budgets.perOrigin, p.Budgets.perModule, p.Budgets.perIdentity), evidence: p.Evidence, workflows: workflows}
}

func (m Manifest) APIVersion() string { return m.apiVersion }
func (m Manifest) Kind() string       { return m.kind }
func (m Manifest) Name() string       { return m.name }
func (m Manifest) Origins() []Origin  { return cloneSlice(m.origins) }
func (m Manifest) Inputs() []InputSource {
	output := make([]InputSource, len(m.inputs))
	for index, input := range m.inputs {
		output[index] = input.Clone()
	}
	return output
}
func (m Manifest) Window() TimeWindow         { return m.window }
func (m Manifest) Transport() TransportPolicy { return m.transport }
func (m Manifest) Modules() []ModuleConfig    { return cloneSlice(m.modules) }
func (m Manifest) Budgets() Budgets {
	return NewBudgets(m.budgets.global, m.budgets.perOrigin, m.budgets.perModule, m.budgets.perIdentity)
}
func (m Manifest) Evidence() EvidenceConfig { return m.evidence }
func (m Manifest) HasStateChangingOperations() bool {
	for _, module := range m.modules {
		if module.IsStateChanging() {
			return true
		}
	}
	for _, workflow := range m.workflows {
		if workflow.safetyClass.IsStateChanging() {
			return true
		}
	}
	return false
}

func (m Manifest) Identities() []Identity {
	output := make([]Identity, len(m.identities))
	for index, identity := range m.identities {
		output[index] = identity.Clone()
	}
	return output
}
func (m Manifest) OwnedObjects() []OwnedObject {
	output := make([]OwnedObject, len(m.objects))
	for index, object := range m.objects {
		output[index] = object.Clone()
	}
	return output
}
func (m Manifest) Workflows() []Workflow {
	output := make([]Workflow, len(m.workflows))
	for index, workflow := range m.workflows {
		output[index] = workflow.Clone()
	}
	return output
}
func (m Manifest) Clone() Manifest {
	return NewManifest(ManifestParams{APIVersion: m.apiVersion, Kind: m.kind, Name: m.name, Origins: m.origins, Inputs: m.inputs, Window: m.window, Transport: m.transport, Identities: m.identities, Objects: m.objects, Modules: m.modules, Budgets: m.budgets, Evidence: m.evidence, Workflows: m.workflows})
}
