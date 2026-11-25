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

## Generated system-level tests

8. Add `sj contract fuzz`. Generate test cases from the document, run them, and report findings without a hand-written suite. Obtain one accepted request per operation before deriving any variant, so a rejected request is reported as untested and never as a pass.
9. Create the records that paths address, reuse accepted values in later calls, and delete the records afterwards. A request that changes or deletes by path identifier must address a record sj created.
10. Re-run each security finding on new records. Emit the executed cases as a suite that `sj contract --suite` replays.
11. Compare the report for the public Petstore service with an answer key written from the contract and manual observation before the engine existed.

| EvoMaster implementation | sj |
| --- | --- |
| Smart sampling orders calls by resource dependency, and a data pool reuses response values. `ResourceSampler.kt`, `DataPool.kt` | Record types come from path templates. Creation runs first and deletion last. Accepted body values feed parameters of the same name. |
| `RestSecurityOracle.kt`: access without authentication (307), anonymous modification (308), leaked stack traces (309), hidden accessible endpoints (310) | `auth_not_enforced` and `invalid_credential_accepted` test the declared scheme directly. `anonymous_modification`, `error_disclosure` and `undeclared_method_accepted` cover the rest. |
| `HttpStatusOracle.kt` and `HttpSemanticsOracle.kt`: status rules and a DELETE that leaves the resource readable (113) | 401 without a challenge, 405 without `Allow`, 201 from GET, PATCH or DELETE, 501 on a documented operation, and `delete_not_effective`. |
| `RestSchemaOracle.kt` (200) and HTTP 500 (100) | The existing response validation and `server_error`. |
| Robustness inputs and XSS payloads | One contract violation per request, omitted optional inputs, and inert quote, markup, template and traversal values. |

Not adopted: evolutionary search and white-box coverage; generated JUnit, Python or JavaScript source (sj emits a replayable YAML suite); oracles that need two users, namely existence leakage (304), 401 instead of 403 (305) and inconsistent write authorization (306), which `sj assess` covers with declared identities; time-based SQL injection (300) and SSRF with a callback listener (302), which sj's payload policy excludes; stored XSS (301); PUT replacement, idempotency, merge-patch and `Location` oracles (114 to 120); repair of a rejected valid request; XML request bodies.

### Petstore result

The answer key holds 45 rows: 15 authentication, 11 disclosure, 12 robustness and 7 contract. Of these, 38 were written on November 25, 2026 from the contract and manual curl observation before the engine existed. Seven were added the same day and are marked in the file: five disclosure rows that sj reported first and curl then confirmed, and two robustness rows that the manual log already showed but the first key omitted.

On November 25, 2026, `make test-petstore-live` reported all 45 rows against `https://petstore.swagger.io/v2` with seeds 20261125, 7 and 3. Each run sent about 390 requests in 100 seconds, obtained an accepted request for all 20 operations, reproduced every authentication, disclosure and robustness finding on new records, and removed its records. The three runs reported the same 72 findings. The authentication and disclosure categories contained no row outside the key apart from the server version banner. The 25 other rows outside the key are 18 contract deviations and 7 accepted invalid inputs, in categories the key does not list exhaustively. A sample was checked by hand. The curl scripts and logs are in `tests/petstore/manual/`.

The local replica and its hardened control were written from the same observations, so they are a repeatable regression test and not independent evidence. The result shows that sj finds the weaknesses in this key on this service. It does not show that the key is complete.

