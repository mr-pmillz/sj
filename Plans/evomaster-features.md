# EvoMaster features for sj

The aim is a repeatable answer to two questions. Does this example request still work for the intended caller? Does the response still satisfy the published API contract?

## What to adapt

I reviewed EvoMaster at `dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a` and sj's OpenAPI loader, HTTP client, private-header transport and CLI.

| EvoMaster implementation | Design for sj |
| --- | --- |
| The HTTP authentication model distinguishes fixed headers from login calls that acquire credentials. [HttpWsAuthenticationInfo.kt](https://github.com/WebFuzzing/EvoMaster/blob/dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a/core/src/main/kotlin/org/evomaster/core/problem/httpws/auth/HttpWsAuthenticationInfo.kt) | Reuse sj's owner-only header file for an existing API key, session cookie, Basic credential or issued bearer token. Resolve security requirements for each operation before sending requests. |
| The response oracle feeds the status, media type and body back into the operation's OpenAPI description. Its tests include an undocumented status and a missing body. [RestSchemaOracle.kt](https://github.com/WebFuzzing/EvoMaster/blob/dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a/core/src/main/kotlin/org/evomaster/core/problem/rest/oracle/RestSchemaOracle.kt) · [RestSchemaOraclesTest.kt](https://github.com/WebFuzzing/EvoMaster/blob/dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a/core/src/test/kotlin/org/evomaster/core/problem/rest/RestSchemaOraclesTest.kt) | Validate example inputs before execution. Check the observed response against the declared status, content type, headers and schema. Let a case assert a business value such as the signed-in user's ID. |
| EvoMaster records individual HTTP statuses for each action and counts distinct endpoints that returned success. [AbstractRestFitness.kt](https://github.com/WebFuzzing/EvoMaster/blob/dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a/core/src/main/kotlin/org/evomaster/core/problem/rest/service/fitness/AbstractRestFitness.kt#L388) · [Statistics.kt](https://github.com/WebFuzzing/EvoMaster/blob/dd063b4f9fa6bf8ee68f69d41c936dcc1b0ee22a/core/src/main/kotlin/org/evomaster/core/search/service/Statistics.kt#L947) | Count distinct exercised operations and matched response declarations against the whole document. Repeating a case must not inflate either count. |

## Implementation and acceptance criteria

1. Add `sj contract` for explicit, ordered examples in a YAML suite. Accept a Swagger 2 or OpenAPI 3 document and an explicit API base URL. Check path and query parameters and optional JSON bodies. Reject invalid suites before sending their first operation. Apply sj's existing method and dangerous-path safeguards.
2. Honor global security, operation overrides, alternatives and combinations. A case marked `authenticated: true` must match a nonempty declared requirement. Scope credential delivery to the explicit API origin and the cases that use authentication. Exercise a local endpoint that actually checks the credential and returns the caller's identity.
3. Report expected versus observed status, exact/range/default response matching, schema validation and optional JSON Pointer assertions. Return a failing exit code on a failed case. Emit a JSON report suitable for CI with case outcomes and coverage counts. Keep credentials, concrete parameter values and response bodies out of that report.
4. Update the Go minimum to 1.27.4 and refresh module versions. Verify the module graph, run the repository tests, race detector, vet, lint and build, and smoke-test the built CLI.
5. Run one live example with the published demo key on the inventory operation. Record whether the credentialed request reached the service and whether its response conformed. The live example measures one operation. A local fixture with a known identity supplies the authentication regression test. [Petstore Swagger document](https://petstore.swagger.io/v2/swagger.json)

## Full-document regression benchmark

6. Generate an ordered case for each declared method and path. Use documented example values and defaults, allow fixture overrides, and identify missing inputs. Generation may read a specification URL. Only the separate suite runner sends operation requests.
7. Exercise the Petstore contract's JSON, URL-encoded form and multipart examples. Keep the all-operation benchmark on a disposable loopback service with known test data. Compare the complete set of reported outcomes to an independent answer key, including missed and spurious failures and distinct coverage.

On November 21, 2026, the live credentialed inventory case received HTTP 200 and passed JSON schema validation. It exercised 1 of 20 operations and matched 1 of 36 response declarations. The inventory response does not identify a caller. The local authentication fixture checks the signed-in subject and rejects an incorrect credential.
