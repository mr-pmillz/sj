package cli

func fullWorkflowAssessmentTemplate() string {
	return `apiVersion: sj.dev/v1alpha1
kind: Assessment
metadata:
  name: workflow-assessment
spec:
  origins: ["https://api.example"]
  inputs:
    - name: workflow-results
      kind: sj-results
      path: $workflow.automate
      baseURL: "https://api.example"
  window: {start: "2020-01-01T00:00:00Z", end: "2099-01-01T00:00:00Z"}
  transport:
    proxy: {required: false, url: ""}
    tls: {insecureSkipVerify: false, justification: ""}
    redirects: {sameOriginOnly: true, max: 0}
  identities:
    - name: user-a
      role: member
      tenant: tenant-a
      headers: {Authorization: "env:SJ_WORKFLOW_TOKEN_A"}
    - name: user-b
      role: member
      tenant: tenant-b
      headers: {Authorization: "env:SJ_WORKFLOW_TOKEN_B"}
  ownedObjects:
    - name: item-a
      type: item
      identifier: "101"
      owner: user-a
      tenant: tenant-a
      provenance: authorized-fixture
      stable: true
      expectedAccess: {user-a: allow, user-b: deny, anonymous: deny}
  modules:
    - {name: bola, enabled: true, safetyClass: S1}
  budgets:
    global: {maxRequests: 20, maxRequestBytes: 1048576, maxResponseBytes: 1048576, requestsPerSecond: 10}
  evidence:
    storeResponseBodies: false
    maxArtifactBytes: 1048576
    retention: 1h
    includeSensitiveExports: false
  workflows: []
`
}
