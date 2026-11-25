# Manual observations behind the Petstore answer key

These scripts and logs are the evidence for `../answer-key.yaml`. They use
curl only and do not involve sj.

| File | Contents |
| --- | --- |
| `probe.sh`, `probe2.sh` | The observations the first version of the key was written from, before the fuzz engine existed |
| `probe3.sh` | Behaviours needed for the local replica, recorded before sj's first live run |
| `verify.sh` | Checks of rows that sj reported beyond the first key |
| `probe4.sh` | The cause of the `uploadImage` HTTP 500, and how the service treats a body identity that differs from the path |
| `probe-20261125.log` | Output of the four probe scripts, in the order they ran on 2026-11-25 |
| `verify-20261125.log` | Output of `verify.sh` |

Each script creates records under random identifiers and deletes them. One
request in `probe4.sh` created a user with a null username, which the public
service accepted and which cannot be deleted. Do not run that request again.

Response bodies in the logs are truncated and come from a public demo
service. They can include records that other visitors created.
