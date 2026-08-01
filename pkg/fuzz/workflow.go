package fuzz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/mr-pmillz/sj/pkg/apitest"
	"golang.org/x/net/http/httpguts"
)

const maximumWorkflowBytes int64 = 1024 * 1024

type WorkflowFile struct {
	Workflows []Workflow `json:"workflows"`
}

type Workflow struct {
	Name  string         `json:"name"`
	Steps []WorkflowStep `json:"steps"`
}

type WorkflowStep struct {
	Name             string            `json:"name"`
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	Identity         string            `json:"identity,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             json.RawMessage   `json:"body,omitempty"`
	ExpectStatus     []int             `json:"expect_status,omitempty"`
	Capture          map[string]string `json:"capture,omitempty"`
	AssertJSON       map[string]any    `json:"assert_json,omitempty"`
	VerifySideEffect bool              `json:"verify_side_effect,omitempty"`
}

func LoadWorkflows(path string) ([]Workflow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workflow file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumWorkflowBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read workflow file: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close workflow file: %w", closeErr)
	}
	if int64(len(data)) > maximumWorkflowBytes {
		return nil, fmt.Errorf("workflow file exceeds %d-byte limit", maximumWorkflowBytes)
	}
	var workflowFile WorkflowFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&workflowFile); err != nil {
		return nil, fmt.Errorf("decode workflow file: %w", err)
	}
	if len(workflowFile.Workflows) == 0 {
		return nil, errors.New("workflow file contains no workflows")
	}
	for workflowIndex, workflow := range workflowFile.Workflows {
		if strings.TrimSpace(workflow.Name) == "" || len(workflow.Steps) == 0 {
			return nil, fmt.Errorf("workflow %d must define a name and at least one step", workflowIndex+1)
		}
		for stepIndex, step := range workflow.Steps {
			if strings.TrimSpace(step.Name) == "" || strings.TrimSpace(step.Method) == "" || strings.TrimSpace(step.URL) == "" {
				return nil, fmt.Errorf("workflow %q step %d must define name, method, and URL", workflow.Name, stepIndex+1)
			}
			if len(step.Body) > apitest.MaximumPayloadBytes || len(step.URL) > 8*1024 {
				return nil, fmt.Errorf("workflow %q step %q exceeds bounded request size limits", workflow.Name, step.Name)
			}
		}
	}
	return workflowFile.Workflows, nil
}

func validateWorkflows(workflows []Workflow, identities []Identity) error {
	identityNames := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		identityNames[identity.Name] = struct{}{}
	}
	for workflowIndex, workflow := range workflows {
		if err := validateWorkflow(workflow, workflowIndex, identityNames); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkflow(workflow Workflow, index int, identityNames map[string]struct{}) error {
	if strings.TrimSpace(workflow.Name) == "" || len(workflow.Steps) == 0 {
		return fmt.Errorf("workflow %d must define a name and at least one step", index+1)
	}
	for stepIndex, step := range workflow.Steps {
		if err := validateWorkflowStep(workflow.Name, step, stepIndex, identityNames); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkflowStep(workflowName string, step WorkflowStep, index int, identityNames map[string]struct{}) error {
	if strings.TrimSpace(step.Name) == "" || !validMethod(step.Method) || strings.TrimSpace(step.URL) == "" || strings.TrimSpace(step.URL) != step.URL {
		return fmt.Errorf("workflow %q step %d must define a name, valid HTTP method, and URL", workflowName, index+1)
	}
	parsedURL, err := url.Parse(step.URL)
	if err != nil || parsedURL.User != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("workflow %q step %q must use an absolute http(s) URL without user information", workflowName, step.Name)
	}
	if len(step.Body) > apitest.MaximumPayloadBytes || len(step.URL) > 8*1024 {
		return fmt.Errorf("workflow %q step %q exceeds bounded request size limits", workflowName, step.Name)
	}
	if err := validateWorkflowIdentity(workflowName, step, identityNames); err != nil {
		return err
	}
	if err := validateWorkflowHeaders(workflowName, step); err != nil {
		return err
	}
	if err := validateWorkflowStatuses(workflowName, step); err != nil {
		return err
	}
	return validateWorkflowCaptures(workflowName, step)
}

func validateWorkflowIdentity(workflowName string, step WorkflowStep, identityNames map[string]struct{}) error {
	if step.Identity == "" {
		return nil
	}
	if _, exists := identityNames[step.Identity]; !exists {
		return fmt.Errorf("workflow %q step %q references unknown identity %q", workflowName, step.Name, step.Identity)
	}
	return nil
}

func validateWorkflowHeaders(workflowName string, step WorkflowStep) error {
	for name, value := range step.Headers {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("workflow %q step %q contains an invalid header", workflowName, step.Name)
		}
	}
	return nil
}

func validateWorkflowStatuses(workflowName string, step WorkflowStep) error {
	for _, status := range step.ExpectStatus {
		if status < 100 || status > 599 {
			return fmt.Errorf("workflow %q step %q contains invalid expected status %d", workflowName, step.Name, status)
		}
	}
	return nil
}

func validateWorkflowCaptures(workflowName string, step WorkflowStep) error {
	for variable, path := range step.Capture {
		if strings.TrimSpace(variable) == "" || strings.TrimSpace(path) == "" {
			return fmt.Errorf("workflow %q step %q contains an empty capture name or path", workflowName, step.Name)
		}
	}
	return nil
}

func validMethod(method string) bool {
	if method == "" || strings.TrimSpace(method) != method {
		return false
	}
	for _, character := range method {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}

func executeWorkflows(
	ctx context.Context,
	client *http.Client,
	report *Report,
	state *probeRunState,
	identities []Identity,
	options Options,
	wait waitFunc,
) error {
	identityMap := make(map[string]Identity, len(identities))
	for _, identity := range identities {
		identityMap[identity.Name] = identity
	}
	executor := workflowExecutor{
		ctx: ctx, client: client, report: report, state: state,
		identities: identities, identityMap: identityMap, options: options, wait: wait,
	}
	for _, workflow := range options.Workflows {
		stop, err := executor.execute(workflow)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}

type workflowExecutor struct {
	ctx         context.Context
	client      *http.Client
	report      *Report
	state       *probeRunState
	identities  []Identity
	identityMap map[string]Identity
	options     Options
	wait        waitFunc
}

type workflowStepOutcome int

const (
	workflowStepContinue workflowStepOutcome = iota
	workflowStepNextWorkflow
	workflowStepStop
)

func (executor *workflowExecutor) execute(workflow Workflow) (bool, error) {
	unsafeSteps := workflowUnsafeSteps(workflow)
	if unsafeSteps > 0 && !executor.options.AcceptRisk {
		executor.report.Summary.SkippedUnsafe += unsafeSteps
		return false, nil
	}
	variables := make(map[string]string)
	for index, step := range workflow.Steps {
		outcome, err := executor.executeStep(workflow, step, variables)
		if err != nil {
			return false, err
		}
		switch outcome {
		case workflowStepStop:
			return true, nil
		case workflowStepNextWorkflow:
			executor.recordBlockedWorkflowSteps(workflow.Steps[index+1:], variables)
			return false, nil
		case workflowStepContinue:
		}
	}
	return false, nil
}

func (executor *workflowExecutor) recordBlockedWorkflowSteps(
	steps []WorkflowStep,
	variables map[string]string,
) {
	if !executor.options.ContinueOnTargetError {
		return
	}
	for _, step := range steps {
		target := substituteWorkflowVariables(step.URL, variables)
		if executor.state.originBlocked(target) {
			executor.report.Summary.SkippedIsolated++
		}
	}
}

func workflowUnsafeSteps(workflow Workflow) int {
	count := 0
	for _, step := range workflow.Steps {
		if stateChanging(step.Method) {
			count++
		}
	}
	return count
}

func (executor *workflowExecutor) executeStep(workflow Workflow, step WorkflowStep, variables map[string]string) (workflowStepOutcome, error) {
	if executor.report.Summary.Requests >= executor.options.MaxRequests {
		executor.report.Summary.RequestBudgetHit = true
		return workflowStepStop, nil
	}
	identity, err := executor.stepIdentity(workflow, step, variables)
	if err != nil {
		return workflowStepStop, err
	}
	plan := workflowProbePlan(workflow, step, variables, identity)
	if executor.options.ContinueOnTargetError && executor.state.originBlocked(plan.targetURL) {
		executor.report.Summary.SkippedIsolated++
		return workflowStepNextWorkflow, nil
	}
	if executor.report.Summary.Requests > 0 {
		if err := executor.wait(executor.ctx, executor.options.Delay); err != nil {
			return workflowStepStop, fmt.Errorf("workflow pacing canceled: %w", err)
		}
	}
	probe, responseBody := executeProbe(executor.ctx, executor.client, plan, executor.options)
	executor.report.Probes = append(executor.report.Probes, probe)
	updateSummary(&executor.report.Summary, probe)
	if shouldStopForRateLimit(probe) {
		executor.report.Summary.RateLimited = true
		if executor.options.ContinueOnTargetError && executor.state.blockOrigin(plan.targetURL) {
			executor.report.Summary.RateLimitedOrigins++
			return workflowStepNextWorkflow, nil
		}
		return workflowStepStop, nil
	}
	if executor.options.ContinueOnTargetError && executor.state.recordTransportResult(
		plan.targetURL, probe.targetOriginTransportFailure,
	) {
		executor.report.Summary.TransportLimitedOrigins++
		return workflowStepNextWorkflow, nil
	}
	if !executor.verifyStep(workflow, step, plan, probe, responseBody) {
		return workflowStepNextWorkflow, nil
	}
	if step.VerifySideEffect {
		executor.report.Summary.SideEffectsVerified++
	}
	if err := captureWorkflowVariables(workflow, step, responseBody, variables); err != nil {
		return workflowStepStop, err
	}
	return workflowStepContinue, nil
}

func (executor *workflowExecutor) stepIdentity(workflow Workflow, step WorkflowStep, variables map[string]string) (Identity, error) {
	identity := cloneIdentity(executor.identities[0])
	if step.Identity != "" {
		selected, exists := executor.identityMap[step.Identity]
		if !exists {
			return Identity{}, fmt.Errorf("workflow %q step %q references unknown identity %q", workflow.Name, step.Name, step.Identity)
		}
		identity = cloneIdentity(selected)
	}
	for name, value := range step.Headers {
		identity.Headers[name] = substituteWorkflowVariables(value, variables)
	}
	return identity, nil
}

func workflowProbePlan(workflow Workflow, step WorkflowStep, variables map[string]string, identity Identity) plannedProbe {
	return plannedProbe{
		method: strings.ToUpper(step.Method), targetURL: substituteWorkflowVariables(step.URL, variables),
		body: []byte(substituteWorkflowVariables(string(step.Body), variables)), contentType: "application/json",
		caseName: "workflow:" + workflow.Name + ":" + step.Name, category: "business_workflow", identity: identity,
	}
}

func (executor *workflowExecutor) verifyStep(workflow Workflow, step WorkflowStep, plan plannedProbe, probe ProbeResult, responseBody []byte) bool {
	statusOK := expectedStatus(step.ExpectStatus, probe.Status)
	assertionsOK := assertWorkflowJSON(responseBody, step.AssertJSON)
	if statusOK && assertionsOK {
		return true
	}
	executor.report.Findings = append(executor.report.Findings, Finding{
		Severity: "medium", Category: "business_workflow_verification", Title: "Business workflow step did not satisfy its read-back contract",
		Method: plan.method, URL: plan.targetURL,
		Evidence: fmt.Sprintf("workflow=%s step=%s identity=%s status=%d status_expected=%t assertions_passed=%t", workflow.Name, step.Name, plan.identity.Name, probe.Status, statusOK, assertionsOK),
		OWASP:    []string{"API6:2023"},
	})
	return false
}

func captureWorkflowVariables(workflow Workflow, step WorkflowStep, responseBody []byte, variables map[string]string) error {
	if len(step.Capture) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return fmt.Errorf("workflow %q step %q capture requires a JSON response: %w", workflow.Name, step.Name, err)
	}
	for variable, path := range step.Capture {
		value, exists := jsonPathValue(decoded, path)
		if !exists {
			return fmt.Errorf("workflow %q step %q capture path %q was not found", workflow.Name, step.Name, path)
		}
		variables[variable] = fmt.Sprint(value)
	}
	return nil
}

func cloneIdentity(identity Identity) Identity {
	cloned := Identity{Name: identity.Name, Headers: make(map[string]string, len(identity.Headers))}
	for name, value := range identity.Headers {
		cloned.Headers[name] = value
	}
	return cloned
}

func expectedStatus(expected []int, actual int) bool {
	if len(expected) == 0 {
		return actual >= 200 && actual < 300
	}
	for _, status := range expected {
		if status == actual {
			return true
		}
	}
	return false
}

func assertWorkflowJSON(body []byte, assertions map[string]any) bool {
	if len(assertions) == 0 {
		return true
	}
	var decoded any
	if json.Unmarshal(body, &decoded) != nil {
		return false
	}
	for path, expected := range assertions {
		actual, exists := jsonPathValue(decoded, path)
		if !exists || fmt.Sprint(actual) != fmt.Sprint(expected) {
			return false
		}
	}
	return true
}

func jsonPathValue(value any, path string) (any, bool) {
	current := value
	path = strings.TrimPrefix(strings.TrimSpace(path), "$")
	path = strings.TrimPrefix(path, ".")
	for _, segment := range strings.Split(path, ".") {
		segment = strings.Trim(segment, "'[]")
		if segment == "" {
			continue
		}
		switch typed := current.(type) {
		case map[string]any:
			next, exists := typed[segment]
			if !exists || next == nil {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func substituteWorkflowVariables(value string, variables map[string]string) string {
	for name, replacement := range variables {
		value = strings.ReplaceAll(value, "{{"+name+"}}", replacement)
	}
	return value
}
