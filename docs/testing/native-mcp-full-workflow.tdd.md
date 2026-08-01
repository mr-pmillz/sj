# Native MCP full-workflow TDD evidence

## Source and user journey

No external plan was supplied. The journey was derived from the request:

> As a local MCP client, I want to invoke sj's complete full workflow with one
> typed tool call, so that I do not need to upload an assessment manifest or
> coordinate the individual discovery, automation, fuzz, collection, report,
> and assessment tools.

## RED/GREEN task report

| Behavior | RED evidence | GREEN evidence | Guarantee |
|---|---|---|---|
| Advertise and policy-check `run_full_workflow` | `go test ./pkg/mcpserver -run 'TestServerAdvertisesTypedToolsAndSafetyAnnotations\|TestRunFullWorkflowTool' -count=1` failed to compile because the typed request, output, runner, and option did not exist. | The same command passed after implementing the tool contract and policy checks. | The tool has inferred schemas, active/destructive annotations, host allowlisting, root confinement, automatic-assessment defaults, and independent POST/PATCH gates. |
| Invoke the existing workflow in process | `go test ./internal/cli -run TestExecuteMCPFullWorkflowMaterializesURLsAndReturnsDurableArtifacts -count=1` failed because `executeMCPFullWorkflow` did not exist. | The same command passed after adding the adapter. | URL arrays are materialized into a private temporary file, the existing stage orchestration runs without a subprocess, the server key is passed without environment mutation, and the temporary file is removed. |
| Keep MCP stdout protocol-clean | The first live MCP call failed with `invalid character 'T' looking for beginning of value`; the adapter test then failed because automation inherited `console` output. A second live call failed with `invalid character 'G'` from the collection completion message. `TestRunCollectionKeepsOperationalMessageOffStdout` reproduced the latter with the exact stdout text. | Both focused tests passed after selecting structured workflow output and moving the collection diagnostic to stderr. A repeated real MCP call completed successfully. | Human-readable CLI output cannot corrupt the MCP JSON stream on the native path. |

## Live integration evidence

The rebuilt stdio MCP server received one `run_full_workflow` call with one
authorized CPT OpenAPI URL through `socks5://127.0.0.1:9000`. It returned
`completed=true`, assessment ID `905feaccdb524b310b5074a51289be9a`, and 17
artifact entries. The artifacts recorded five GET automation requests and 16
GET fuzz probes, with zero POST, PATCH, or DELETE requests. The anonymous
assessment snapshot was sealed as `succeeded` with zero identities and zero
ownership-backed plan nodes.

## Coverage and known gaps

Unit and integration coverage includes accepted direct specifications plus
rejection before runner invocation for disabled active access, disallowed
hosts, out-of-root output, missing risk acknowledgement, disabled destructive
authority, and missing source mode. Stored brute-run resume is mapped to the
same already-tested CLI workflow but was not repeated against live retained
evidence in this MCP-specific smoke.

`go test -cover ./pkg/mcpserver -count=1` reports 78.2% for the complete legacy
MCP package. The newly added feature functions are above the 80% changed-code
target: `runFullWorkflow` 90.9%, `validateFullWorkflowInput` 88.1%, and
`validateFullWorkflowSources` 95.0%. Raising unrelated legacy MCP branches to a
package-wide 80% is outside this feature's scope.

Checkpoint commits preserve the contract RED (`9445731`) and adapter RED
(`248de5e`). The GREEN implementation commit containing this report records the
complete passing suite and live smoke evidence.
