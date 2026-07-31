package manifest

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/assessment/model"
)

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	cookiePattern  = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)
)

func validateAndBuild(doc document, options LoadOptions) (model.Manifest, error) {
	if doc.APIVersion != model.APIVersionV1Alpha1 {
		return model.Manifest{}, validation("apiVersion", "unsupported API version")
	}
	if doc.Kind != model.KindAssessment {
		return model.Manifest{}, validation("kind", "unsupported manifest kind")
	}
	if !validName(doc.Metadata.Name) {
		return model.Manifest{}, validation("metadata.name", "must be a non-empty DNS-safe identifier")
	}

	origins, originSet, err := validateOrigins(doc.Spec.Origins)
	if err != nil {
		return model.Manifest{}, err
	}
	inputs, err := validateInputs(doc.Spec.Inputs, originSet, options)
	if err != nil {
		return model.Manifest{}, err
	}
	windowValue, err := validateWindow(doc.Spec.Window)
	if err != nil {
		return model.Manifest{}, err
	}
	transportValue, err := validateTransport(doc.Spec.Transport)
	if err != nil {
		return model.Manifest{}, err
	}
	identities, identitySet, err := validateIdentities(doc.Spec.Identities, options)
	if err != nil {
		return model.Manifest{}, err
	}
	identityTenants := make(map[string]string, len(identities))
	for _, identity := range identities {
		identityTenants[identity.Name()] = identity.Tenant()
	}
	objects, objectSet, err := validateObjects(doc.Spec.OwnedObjects, identityTenants)
	if err != nil {
		return model.Manifest{}, err
	}
	modules, moduleSet, err := validateModules(doc.Spec.Modules)
	if err != nil {
		return model.Manifest{}, err
	}
	if err := validateInputSelections(inputs, moduleSet); err != nil {
		return model.Manifest{}, err
	}
	budgetsValue, err := validateBudgets(doc.Spec.Budgets, originSet, moduleSet, identitySet)
	if err != nil {
		return model.Manifest{}, err
	}
	evidenceValue, err := validateEvidence(doc.Spec.Evidence, doc.Spec.Budgets.Global, options)
	if err != nil {
		return model.Manifest{}, err
	}
	workflows, workflowSet, err := validateWorkflows(doc.Spec.Workflows, identitySet, objectSet)
	if err != nil {
		return model.Manifest{}, err
	}
	for index, object := range objects {
		if object.RollbackWorkflow() != "" {
			if _, ok := workflowSet[object.RollbackWorkflow()]; !ok {
				return model.Manifest{}, validation(fmt.Sprintf("spec.ownedObjects[%d].rollbackWorkflow", index), "references an unknown workflow")
			}
		}
	}

	return model.NewManifest(model.ManifestParams{
		APIVersion: doc.APIVersion,
		Kind:       doc.Kind,
		Name:       doc.Metadata.Name,
		Origins:    origins,
		Inputs:     inputs,
		Window:     windowValue,
		Transport:  transportValue,
		Identities: identities,
		Objects:    objects,
		Modules:    modules,
		Budgets:    budgetsValue,
		Evidence:   evidenceValue,
		Workflows:  workflows,
	}), nil
}

func validateOrigins(raw []string) ([]model.Origin, map[string]struct{}, error) {
	if len(raw) == 0 {
		return nil, nil, validation("spec.origins", "at least one exact origin is required")
	}
	result := make([]model.Origin, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, value := range raw {
		canonical, err := exactOrigin(value)
		if err != nil {
			return nil, nil, validation(fmt.Sprintf("spec.origins[%d]", index), err.Error())
		}
		if _, exists := seen[canonical]; exists {
			return nil, nil, validation(fmt.Sprintf("spec.origins[%d]", index), "duplicate origin")
		}
		seen[canonical] = struct{}{}
		result = append(result, model.NewOrigin(canonical))
	}
	return result, seen, nil
}

func exactOrigin(raw string) (string, error) {
	parsed, err := parseNetworkURL(raw)
	if err != nil {
		return "", err
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("must contain only scheme and authority")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func parseNetworkURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n") {
		return nil, fmt.Errorf("must be a non-empty URL without surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" {
		return nil, fmt.Errorf("must be a valid absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if parsed.Hostname() == "" || strings.Contains(parsed.Hostname(), "*") {
		return nil, fmt.Errorf("host must be exact and non-empty")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("embedded credentials are prohibited")
	}
	return parsed, nil
}

func validateInputs(raw []inputSource, origins map[string]struct{}, options LoadOptions) ([]model.InputSource, error) {
	if len(raw) == 0 {
		return nil, validation("spec.inputs", "at least one passive input source is required")
	}
	result := make([]model.InputSource, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, input := range raw {
		field := fmt.Sprintf("spec.inputs[%d]", index)
		if !validName(input.Name) {
			return nil, validation(field+".name", "must be a non-empty identifier")
		}
		if _, exists := seen[input.Name]; exists {
			return nil, validation(field+".name", "duplicate input name")
		}
		seen[input.Name] = struct{}{}
		kind, ok := model.ParseInputKind(input.Kind)
		if !ok {
			return nil, validation(field+".kind", "must be openapi or sj-results")
		}
		sources := boolInt(input.Path != "") + boolInt(input.URL != "") + boolInt(input.RunID != "")
		if sources != 1 {
			return nil, validation(field, "exactly one of path, url, or runId is required")
		}
		if input.Path != "" {
			if !filepath.IsAbs(input.Path) {
				return nil, validation(field+".path", "must be absolute")
			}
			if err := validateRegularReference(input.Path, options.MaxInputFileBytes, false); err != nil {
				return nil, fmt.Errorf("%s.path: %w", field, err)
			}
		}
		if input.URL != "" {
			if err := validateScopedURL(input.URL, origins); err != nil {
				return nil, validation(field+".url", err.Error())
			}
		}
		if input.RunID != "" && !validName(input.RunID) {
			return nil, validation(field+".runId", "must be a non-empty identifier")
		}
		if kind == model.InputKindOpenAPI && input.RunID != "" {
			return nil, validation(field+".runId", "is only valid for sj-results")
		}
		if input.BaseURL != "" {
			if err := validateScopedURL(input.BaseURL, origins); err != nil {
				return nil, validation(field+".baseURL", err.Error())
			}
		}
		if err := validateUniqueNames(field+".operations", input.Operations); err != nil {
			return nil, err
		}
		if err := validateUniqueNames(field+".modules", input.Modules); err != nil {
			return nil, err
		}
		result = append(result, model.NewInputSource(input.Name, kind, input.Path, input.URL, input.RunID, input.BaseURL, input.Operations, input.Modules))
	}
	return result, nil
}

func validateScopedURL(raw string, origins map[string]struct{}) error {
	parsed, err := parseNetworkURL(raw)
	if err != nil {
		return err
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("query strings and fragments are prohibited")
	}
	origin := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
	if _, allowed := origins[origin]; !allowed {
		return fmt.Errorf("origin is not present in spec.origins")
	}
	return nil
}

func validateWindow(raw window) (model.TimeWindow, error) {
	start, err := time.Parse(time.RFC3339, raw.Start)
	if err != nil {
		return model.TimeWindow{}, validation("spec.window.start", "must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, raw.End)
	if err != nil {
		return model.TimeWindow{}, validation("spec.window.end", "must be RFC3339")
	}
	if !end.After(start) {
		return model.TimeWindow{}, validation("spec.window", "end must be after start")
	}
	return model.NewTimeWindow(start, end), nil
}

func validateTransport(raw transport) (model.TransportPolicy, error) {
	if raw.Proxy.Required && raw.Proxy.URL == "" {
		return model.TransportPolicy{}, validation("spec.transport.proxy.url", "is required when proxy.required is true")
	}
	if raw.Proxy.URL != "" {
		proxyURL, err := url.Parse(raw.Proxy.URL)
		if err != nil || proxyURL.Hostname() == "" || proxyURL.Opaque != "" {
			return model.TransportPolicy{}, validation("spec.transport.proxy.url", "must be an absolute proxy URL")
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return model.TransportPolicy{}, validation("spec.transport.proxy.url", "unsupported proxy scheme")
		}
		if proxyURL.User != nil {
			return model.TransportPolicy{}, validation("spec.transport.proxy.url", "embedded credentials are prohibited")
		}
		if proxyURL.RawQuery != "" || proxyURL.Fragment != "" || proxyURL.Path != "" {
			return model.TransportPolicy{}, validation("spec.transport.proxy.url", "must contain only scheme and authority")
		}
	}
	if raw.TLS.InsecureSkipVerify && strings.TrimSpace(raw.TLS.Justification) == "" {
		return model.TransportPolicy{}, validation("spec.transport.tls.justification", "is required when verification is disabled")
	}
	if raw.Redirects.Max < 0 || raw.Redirects.Max > 20 {
		return model.TransportPolicy{}, validation("spec.transport.redirects.max", "must be between 0 and 20")
	}
	if raw.Redirects.Max > 0 && !raw.Redirects.SameOriginOnly {
		return model.TransportPolicy{}, validation("spec.transport.redirects.sameOriginOnly", "must be true when redirects are enabled")
	}
	return model.NewTransportPolicy(
		model.NewProxyPolicy(raw.Proxy.Required, raw.Proxy.URL),
		model.NewTLSPolicy(raw.TLS.InsecureSkipVerify, raw.TLS.Justification),
		model.NewRedirectPolicy(raw.Redirects.SameOriginOnly, raw.Redirects.Max),
	), nil
}

func validateIdentities(raw []identity, options LoadOptions) ([]model.Identity, map[string]struct{}, error) {
	result := make([]model.Identity, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, identity := range raw {
		field := fmt.Sprintf("spec.identities[%d]", index)
		if !validName(identity.Name) || identity.Name == "anonymous" {
			return nil, nil, validation(field+".name", "must be a unique identifier other than anonymous")
		}
		if strings.TrimSpace(identity.Role) == "" || strings.TrimSpace(identity.Tenant) == "" {
			return nil, nil, validation(field, "role and tenant are required")
		}
		if _, exists := seen[identity.Name]; exists {
			return nil, nil, validation(field+".name", "duplicate identity")
		}
		seen[identity.Name] = struct{}{}
		headers, err := validateSecretMap(field+".headers", identity.Headers, options, true)
		if err != nil {
			return nil, nil, err
		}
		cookies, err := validateSecretMap(field+".cookies", identity.Cookies, options, false)
		if err != nil {
			return nil, nil, err
		}
		if len(headers) == 0 && len(cookies) == 0 {
			return nil, nil, validation(field, "must contain at least one header or cookie secret reference")
		}
		result = append(result, model.NewIdentity(identity.Name, identity.Role, identity.Tenant, headers, cookies))
	}
	return result, seen, nil
}

func validateSecretMap(field string, raw map[string]string, options LoadOptions, header bool) (map[string]model.SecretRef, error) {
	result := make(map[string]model.SecretRef, len(raw))
	canonicalSeen := make(map[string]struct{}, len(raw))
	for name, value := range raw {
		canonical := name
		if header {
			canonical = http.CanonicalHeaderKey(name)
			if canonical == "" || strings.ContainsAny(name, "\r\n:") {
				return nil, validation(field, "contains an invalid header name")
			}
		} else if !cookiePattern.MatchString(name) {
			return nil, validation(field, "contains an invalid cookie name")
		}
		lookup := strings.ToLower(canonical)
		if _, duplicate := canonicalSeen[lookup]; duplicate {
			return nil, validation(field, "contains duplicate names after canonicalization")
		}
		canonicalSeen[lookup] = struct{}{}
		ref, err := parseSecretRef(value, options)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		result[canonical] = ref
	}
	return result, nil
}

func parseSecretRef(raw string, options LoadOptions) (model.SecretRef, error) {
	scheme, target, found := strings.Cut(raw, ":")
	if !found || target == "" {
		return model.SecretRef{}, ErrSecretReference
	}
	switch scheme {
	case "env":
		if !envNamePattern.MatchString(target) {
			return model.SecretRef{}, ErrSecretReference
		}
		return model.NewSecretRef(model.SecretSourceEnvironment, target), nil
	case "file":
		if !filepath.IsAbs(target) {
			return model.SecretRef{}, ErrSecretReference
		}
		if err := validateRegularReference(target, options.MaxSecretFileBytes, true); err != nil {
			return model.SecretRef{}, err
		}
		return model.NewSecretRef(model.SecretSourceFile, target), nil
	default:
		return model.SecretRef{}, ErrSecretReference
	}
}

func validateRegularReference(path string, maxBytes int64, secret bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: referenced file is unavailable", ErrUnsafeFile)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: reference must be a regular non-symlink file", ErrUnsafeFile)
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("%w: referenced file exceeds its size limit", ErrUnsafeFile)
	}
	if secret && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: secret file must not be accessible by group or other", ErrUnsafeFile)
	}
	return nil
}

func validateObjects(raw []ownedObject, identityTenants map[string]string) ([]model.OwnedObject, map[string]model.OwnedObject, error) {
	result := make([]model.OwnedObject, 0, len(raw))
	seen := make(map[string]model.OwnedObject, len(raw))
	for index, object := range raw {
		field := fmt.Sprintf("spec.ownedObjects[%d]", index)
		if !validName(object.Name) {
			return nil, nil, validation(field+".name", "must be a non-empty identifier")
		}
		if _, exists := seen[object.Name]; exists {
			return nil, nil, validation(field+".name", "duplicate owned object")
		}
		if strings.TrimSpace(object.Type) == "" || strings.TrimSpace(object.Identifier) == "" {
			return nil, nil, validation(field, "type and identifier are required")
		}
		ownerTenant, exists := identityTenants[object.Owner]
		if !exists {
			return nil, nil, validation(field+".owner", "references an unknown identity")
		}
		if strings.TrimSpace(object.Tenant) == "" || object.Tenant != ownerTenant {
			return nil, nil, validation(field+".tenant", "must match the owner identity tenant")
		}
		if strings.TrimSpace(object.Provenance) == "" {
			return nil, nil, validation(field+".provenance", "is required")
		}
		if len(object.ExpectedAccess) == 0 {
			return nil, nil, validation(field+".expectedAccess", "at least one access expectation is required")
		}
		expected := make(map[string]model.ExpectedAccess, len(object.ExpectedAccess))
		for identityName, rawDecision := range object.ExpectedAccess {
			if identityName != "anonymous" {
				if _, exists := identityTenants[identityName]; !exists {
					return nil, nil, validation(field+".expectedAccess", "references an unknown identity")
				}
			}
			decision, err := model.ParseExpectedAccess(rawDecision)
			if err != nil || decision == model.AccessUnknown {
				return nil, nil, validation(field+".expectedAccess", "must contain allow or deny decisions")
			}
			expected[identityName] = decision
		}
		if expected[object.Owner] != model.AccessAllow {
			return nil, nil, validation(field+".expectedAccess", "must allow the owner identity as a positive control")
		}
		var built model.OwnedObject
		if object.Disposable {
			built = model.NewDisposableOwnedObject(object.Name, object.Type, object.Identifier, object.Owner, object.Tenant, object.Provenance, object.Stable, object.RollbackWorkflow, expected)
		} else {
			built = model.NewOwnedObject(object.Name, object.Type, object.Identifier, object.Owner, object.Tenant, object.Provenance, object.Stable, object.RollbackWorkflow, expected)
		}
		seen[object.Name] = built
		result = append(result, built)
	}
	return result, seen, nil
}

func validateModules(raw []module) ([]model.ModuleConfig, map[string]struct{}, error) {
	if len(raw) == 0 {
		return nil, nil, validation("spec.modules", "at least one module is required")
	}
	result := make([]model.ModuleConfig, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, moduleConfig := range raw {
		field := fmt.Sprintf("spec.modules[%d]", index)
		if !validName(moduleConfig.Name) {
			return nil, nil, validation(field+".name", "must be a non-empty identifier")
		}
		if _, exists := seen[moduleConfig.Name]; exists {
			return nil, nil, validation(field+".name", "duplicate module")
		}
		seen[moduleConfig.Name] = struct{}{}
		class, err := model.ParseSafetyClass(moduleConfig.SafetyClass)
		if err != nil {
			return nil, nil, validation(field+".safetyClass", "must be S0, S1, S2, or S3")
		}
		if class.IsProhibited() {
			return nil, nil, validation(field+".safetyClass", "S4 modules are prohibited")
		}
		result = append(result, model.NewModuleConfig(moduleConfig.Name, moduleConfig.Enabled, class))
	}
	return result, seen, nil
}

func validateInputSelections(inputs []model.InputSource, modules map[string]struct{}) error {
	for index, input := range inputs {
		for _, moduleName := range input.Modules() {
			if _, exists := modules[moduleName]; !exists {
				return validation(fmt.Sprintf("spec.inputs[%d].modules", index), "references an unknown module")
			}
		}
	}
	return nil
}

func validateBudgets(raw budgets, origins, modules, identities map[string]struct{}) (model.Budgets, error) {
	global, err := validateBudget("spec.budgets.global", raw.Global)
	if err != nil {
		return model.Budgets{}, err
	}
	perOrigin := make(map[string]model.BudgetLimit, len(raw.PerOrigin))
	for key, value := range raw.PerOrigin {
		origin, parseErr := exactOrigin(key)
		if parseErr != nil {
			return model.Budgets{}, validation("spec.budgets.perOrigin", "contains an invalid exact origin")
		}
		if _, exists := origins[origin]; !exists {
			return model.Budgets{}, validation("spec.budgets.perOrigin", "references an unauthorized origin")
		}
		limit, limitErr := validateBudget("spec.budgets.perOrigin", value)
		if limitErr != nil {
			return model.Budgets{}, limitErr
		}
		perOrigin[origin] = limit
	}
	perModule, err := validateNamedBudgets("spec.budgets.perModule", raw.PerModule, modules)
	if err != nil {
		return model.Budgets{}, err
	}
	perIdentity, err := validateNamedBudgets("spec.budgets.perIdentity", raw.PerIdentity, identities)
	if err != nil {
		return model.Budgets{}, err
	}
	return model.NewBudgets(global, perOrigin, perModule, perIdentity), nil
}

func validateNamedBudgets(field string, raw map[string]budgetLimit, allowed map[string]struct{}) (map[string]model.BudgetLimit, error) {
	result := make(map[string]model.BudgetLimit, len(raw))
	for name, value := range raw {
		if _, exists := allowed[name]; !exists {
			return nil, validation(field, "references an unknown name")
		}
		limit, err := validateBudget(field, value)
		if err != nil {
			return nil, err
		}
		result[name] = limit
	}
	return result, nil
}

func validateBudget(field string, raw budgetLimit) (model.BudgetLimit, error) {
	if raw.MaxRequests <= 0 || raw.MaxRequestBytes <= 0 || raw.MaxResponseBytes <= 0 || raw.RequestsPerSecond <= 0 {
		return model.BudgetLimit{}, validation(field, "all limits must be positive")
	}
	return model.NewBudgetLimit(raw.MaxRequests, raw.MaxRequestBytes, raw.MaxResponseBytes, raw.RequestsPerSecond), nil
}

func validateEvidence(raw evidence, global budgetLimit, options LoadOptions) (model.EvidenceConfig, error) {
	if raw.MaxArtifactBytes <= 0 {
		return model.EvidenceConfig{}, validation("spec.evidence.maxArtifactBytes", "must be positive")
	}
	if raw.MaxArtifactBytes > global.MaxResponseBytes {
		return model.EvidenceConfig{}, validation("spec.evidence.maxArtifactBytes", "must not exceed the global response-byte budget")
	}
	retention, err := time.ParseDuration(raw.Retention)
	if err != nil || retention <= 0 {
		return model.EvidenceConfig{}, validation("spec.evidence.retention", "must be a positive duration")
	}
	var key model.SecretRef
	if raw.EncryptionKey != "" {
		key, err = parseSecretRef(raw.EncryptionKey, options)
		if err != nil {
			return model.EvidenceConfig{}, fmt.Errorf("spec.evidence.encryptionKey: %w", err)
		}
	}
	if raw.StoreResponseBodies && key.IsZero() {
		return model.EvidenceConfig{}, validation("spec.evidence.encryptionKey", "is required when response body storage is enabled")
	}
	return model.NewEvidenceConfig(raw.StoreResponseBodies, key, raw.MaxArtifactBytes, retention, raw.IncludeSensitiveExports), nil
}

func validateWorkflows(raw []workflow, identities map[string]struct{}, objects map[string]model.OwnedObject) ([]model.Workflow, map[string]struct{}, error) {
	result := make([]model.Workflow, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, workflowConfig := range raw {
		field := fmt.Sprintf("spec.workflows[%d]", index)
		if !validName(workflowConfig.Name) {
			return nil, nil, validation(field+".name", "must be a non-empty identifier")
		}
		if _, exists := seen[workflowConfig.Name]; exists {
			return nil, nil, validation(field+".name", "duplicate workflow")
		}
		seen[workflowConfig.Name] = struct{}{}
		validated, err := validateWorkflow(workflowConfig, field, identities, objects)
		if err != nil {
			return nil, nil, err
		}
		result = append(result, validated)
	}
	return result, seen, nil
}

type workflowPurposeCounts struct {
	mutations int
	readbacks int
	rollbacks int
}

func validateWorkflow(raw workflow, field string, identities map[string]struct{}, objects map[string]model.OwnedObject) (model.Workflow, error) {
	class, err := model.ParseSafetyClass(raw.SafetyClass)
	if err != nil || class.IsProhibited() {
		return model.Workflow{}, validation(field+".safetyClass", "must be S0, S1, S2, or S3")
	}
	fixture, exists := objects[raw.Fixture]
	if !exists {
		return model.Workflow{}, validation(field+".fixture", "references an unknown owned object")
	}
	if len(raw.Steps) == 0 {
		return model.Workflow{}, validation(field+".steps", "must not be empty")
	}
	steps, counts, err := validateWorkflowSteps(raw.Steps, field, identities)
	if err != nil {
		return model.Workflow{}, err
	}
	if err := validateWorkflowSafety(class, fixture, counts, field); err != nil {
		return model.Workflow{}, err
	}
	return model.NewWorkflow(raw.Name, class, raw.Fixture, steps), nil
}

func validateWorkflowSteps(raw []workflowStep, field string, identities map[string]struct{}) ([]model.WorkflowStep, workflowPurposeCounts, error) {
	steps := make([]model.WorkflowStep, 0, len(raw))
	stepNames := make(map[string]struct{}, len(raw))
	counts := workflowPurposeCounts{}
	for index, step := range raw {
		validated, purpose, err := validateWorkflowStep(step, fmt.Sprintf("%s.steps[%d]", field, index), identities, stepNames)
		if err != nil {
			return nil, workflowPurposeCounts{}, err
		}
		counts = counts.withPurpose(purpose)
		steps = append(steps, validated)
	}
	return steps, counts, nil
}

func validateWorkflowStep(raw workflowStep, field string, identities, stepNames map[string]struct{}) (model.WorkflowStep, model.WorkflowPurpose, error) {
	if !validName(raw.Name) || !validName(raw.OperationID) {
		return model.WorkflowStep{}, model.WorkflowPurposeUnknown, validation(field, "name and operationId must be identifiers")
	}
	if _, exists := stepNames[raw.Name]; exists {
		return model.WorkflowStep{}, model.WorkflowPurposeUnknown, validation(field+".name", "duplicate workflow step")
	}
	stepNames[raw.Name] = struct{}{}
	if _, exists := identities[raw.Identity]; !exists {
		return model.WorkflowStep{}, model.WorkflowPurposeUnknown, validation(field+".identity", "references an unknown identity")
	}
	purpose, ok := model.ParseWorkflowPurpose(raw.Purpose)
	if !ok {
		return model.WorkflowStep{}, model.WorkflowPurposeUnknown, validation(field+".purpose", "must be mutation, readback, or rollback")
	}
	method, err := validateWorkflowMethod(strings.ToUpper(raw.Method), purpose, field)
	if err != nil {
		return model.WorkflowStep{}, model.WorkflowPurposeUnknown, err
	}
	return model.NewWorkflowStep(raw.Name, purpose, raw.OperationID, raw.Identity, method), purpose, nil
}

func validateWorkflowMethod(method string, purpose model.WorkflowPurpose, field string) (string, error) {
	switch method {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH":
	default:
		return "", validation(field+".method", "method is prohibited or unsupported")
	}
	switch purpose {
	case model.WorkflowPurposeMutation:
		if method != "POST" && method != "PUT" && method != "PATCH" {
			return "", validation(field+".method", "mutation must use POST, PUT, or PATCH")
		}
	case model.WorkflowPurposeReadback:
		if method != "GET" && method != "HEAD" {
			return "", validation(field+".method", "readback must use GET or HEAD")
		}
	case model.WorkflowPurposeRollback:
		if method != "POST" && method != "PUT" && method != "PATCH" {
			return "", validation(field+".method", "rollback must use POST, PUT, or PATCH")
		}
	}
	return method, nil
}

func (c workflowPurposeCounts) withPurpose(purpose model.WorkflowPurpose) workflowPurposeCounts {
	switch purpose {
	case model.WorkflowPurposeMutation:
		c.mutations++
	case model.WorkflowPurposeReadback:
		c.readbacks++
	case model.WorkflowPurposeRollback:
		c.rollbacks++
	}
	return c
}

func validateWorkflowSafety(class model.SafetyClass, fixture model.OwnedObject, counts workflowPurposeCounts, field string) error {
	if class.IsStateChanging() {
		if !fixture.Disposable() {
			return validation(field+".fixture", "S3 workflow fixture must be explicitly disposable")
		}
		if counts.mutations == 0 || counts.readbacks == 0 || counts.rollbacks == 0 {
			return validation(field, "S3 workflow requires mutation, readback, and rollback steps")
		}
		return nil
	}
	if counts.mutations > 0 || counts.rollbacks > 0 {
		return validation(field, "state-changing steps require safetyClass S3")
	}
	return nil
}

func validateUniqueNames(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validName(value) {
			return validation(field, "contains an invalid identifier")
		}
		if _, exists := seen[value]; exists {
			return validation(field, "contains a duplicate identifier")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validName(value string) bool { return namePattern.MatchString(value) }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func validation(field, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrValidation, field, reason)
}
