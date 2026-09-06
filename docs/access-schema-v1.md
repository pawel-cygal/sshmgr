# SSH access data contracts v1

Status: **frozen for backward compatibility on 2026-08-12**.

This document defines the local data boundary between `sshmgr access`, its
reports, and any future sshmgr Cloud client. The executable source of truth is
`ValidateSnapshot`, `ValidateAccessGraph`, `ValidateOwnershipReview`,
`ValidateOffboardingReport`, `ValidateOffboardingCheck`, `ValidateUploadPlan`,
`ValidateWorkspaceHistory`, `ValidateWorkspaceOwnershipHistory`, and
`ValidateWorkspaceOffboardingHistory`, plus the golden fixtures in
`internal/access/testdata/`.

## Versioning policy

Snapshot, access-graph, ownership-review, offboarding-report,
offboarding-check, offline upload-plan, offline workspace-history, and
workspace-ownership-history/workspace-offboarding-history artifacts each carry
`"schema_version": "1"`.

- snapshot and graph v1 readers ignore unknown JSON fields so optional fields
  can be added; security-boundary identity/upload readers are intentionally
  strict and reject unknown fields;
- existing fields do not change meaning or type within v1;
- fields required by the semantic validators remain required;
- removing or renaming a field, changing an edge meaning, or weakening an
  identity/privacy guarantee requires a new schema version;
- readers reject unsupported versions, trailing JSON values, broken references,
  counters that do not reconcile, and artifact-specific size limits (128 MiB
  snapshots, 40 MiB upload plans with 32 MiB payloads, 256 MiB workspace
  histories, 256 MiB workspace ownership histories, and 256 MiB workspace
  offboarding histories).

The stable fixtures are:

- `internal/access/testdata/snapshot-v1.json`;
- `internal/access/testdata/access-graph-v1.json`;
- `internal/access/testdata/upload-plan-v1.json`;
- `internal/access/testdata/workspace-history-v1.json`;
- `internal/access/testdata/workspace-ownership-history-v1.json`;
- `internal/access/testdata/workspace-offboarding-history-v1.json`.

## Snapshot v1

The snapshot is observed evidence from one bounded, read-only scan. Its root
contains the scan envelope, requested scope, derived summary, local findings,
and normalized host/account/key-source observations.

The optional additive `source_scan_ids` field records the flattened lineage of
a snapshot produced by `access merge`. A directly collected snapshot omits the
field. Merge output requires unique source IDs, sorts the lineage, derives a
stable scan ID from it, rejects overlapping source IDs or host aliases, and
reruns summary and finding analysis over the combined evidence.

Required semantic invariants include:

- RFC3339 timestamps with `completed_at >= started_at`;
- scope mode `current` or `system`, a non-empty selector, and non-negative
  budgets;
- exactly one host record per requested alias;
- coverage limited to `full`, `partial`, or `failed`;
- unique account names within a host;
- inspected key entries only on existing, inspected sources;
- each parsed key has a normalized `SHA256:` fingerprint and algorithm;
- malformed entries carry `parse_error` instead of parsed key material;
- summary, finding-severity, byte, host, account, entry, and unique-key counts
  exactly reconcile with observations.

`partial` and `failed` are evidence boundaries, not successful clean scans.
Consumers must preserve and display them when making an access decision.

### Privacy boundary

Snapshots never contain credentials or private keys. Normalized public-key
text is also omitted unless `scope.include_public_keys` was explicitly enabled
for a non-preflight scan. Default artifacts contain fingerprints, algorithms,
key sizes, authorized-key options/comments, OS account metadata, paths,
permissions, findings, and coverage diagnostics.

Comments are untrusted identity hints. They are not ownership claims and must
never be promoted to a verified person or service identity.

## Access graph v1

The graph is a deterministic projection of one validated snapshot. Node IDs
are stable SHA-256 identifiers derived from the node kind and normalized
identity value.

Node kinds:

- `identity_hint` — an authorized-key comment with
  `verification: unverified_comment`;
- `key` — a normalized SSH fingerprint and algorithm metadata;
- `account` — one OS username on one host;
- `host` — one scanned alias with its coverage.

Edge kinds:

- `claims`: `identity_hint -> key`;
- `authorizes`: `key -> account`, with source path and line evidence;
- `on_host`: `account -> host`.

Validators enforce endpoint types, stable IDs, unique nodes/edges, exactly one
host relation per account, valid evidence locations, and fully reconciled graph
summary counters. Graph JSON deliberately has no public-key field.

## Identity map and ownership review v1

The identity map is a separate, strict local YAML input with
`schema_version: "1"`. It contains human/service identities, their
active/offboarded lifecycle state, and explicit fingerprint claims. A generated
template lists observed fingerprints with empty claims; comments never create
identity records or claims.

Claim evidence states are deliberately narrow:

- `claimed_by_identity` — an explicit assignment, without proof of private-key
  possession;
- `possession_verified` — a separate flow proved possession and recorded an
  RFC3339 `verified_at` timestamp.

Identity-map readers reject unknown fields, unknown identity references,
duplicate identities/fingerprints/claims, malformed SHA256 fingerprints,
invalid lifecycle/evidence states, multiple YAML documents, and files above
8 MiB. Files are atomically written mode `0600`.

Ownership review JSON is a deterministic derived artifact joining one validated
snapshot to one validated identity map. It stores both input identifiers, the
normalized identities and identity-map membership, reconciled counters,
key-level claims, unverified comment hints, and findings for unknown keys,
shared claims, offboarded access, and mapped-but-unobserved keys. The reader
reconstructs the identity map from that self-contained data, verifies its
digest, and then reconciles every summary, flag, evidence list, and finding.
HTML/CSV are projections of the same review. None contains raw public-key text,
credentials, or private keys.

## Offboarding report v1

An offboarding report is a deterministic, identity-scoped projection of one
validated snapshot and the exact ownership review derived from it. Construction
first reruns the complete snapshot/review join, then binds both canonical
inputs by SHA256 digest and records exact observed fingerprint, OS-account,
host, source-path, line, coverage, and `authorized_keys` option evidence.
Shared claims remain attached to each fingerprint so the report never implies
exclusive control of a private key.

The safety envelope is invariant: `mode` is `report_only`, remote changes and
execution are false, source-file digests are absent, and a fresh scan is
required before remediation. Derived warnings preserve offboarded observed
access, shared ownership, unverified claims, incomplete host coverage, mapped
but unobserved keys, and dynamic/certificate-backed authentication sources.
The strict reader rejects unknown fields, trailing JSON, invalid or unsorted
evidence, broken counters/warnings, safety-envelope changes, content-ID
tampering, and artifacts above 64 MiB. JSON, HTML, and CSV outputs are private
mode-`0600` local evidence only. Their content hash is an integrity check, not
a signature or proof of author identity.

## Offboarding check v1

An offboarding check binds a validated baseline offboarding report back to its
exact original snapshot/review pair, then compares it with a different, later
snapshot and its exact review. It classifies identity-scoped access edges as
still observed, not observed, or newly observed and produces one of three
outcomes: `still_present`, `complete`, or `inconclusive`.

`complete` is intentionally narrow. Both scans must have comparable policy and
host sets, the after scan must be distinct and newer, all requested hosts must
have full safe collection, ownership claims must be unchanged, the identity
must remain present and offboarded, and neither scan may expose dynamic-key,
principal-command, or SSH-CA sources. A missing host, partial/failed scan,
unread source, malformed key, truncation, changed explicit-account evidence,
changed ownership, or dynamic source forces `inconclusive`. Any current mapped
edge forces `still_present`. The strict validator recalculates classifications,
reasons, counters, outcome, and content ID; readers reject unknown fields,
trailing JSON, and artifacts above 96 MiB. The artifact is local read-only
evidence, not cryptographic attestation or proof about sources outside the
scanned boundary.

## Offline upload plan v1

An upload plan is a deterministic local preview of one possible Cloud
request. Creating or inspecting it never performs a network operation. The
strict envelope binds a lowercase workspace slug, artifact type and `scan_id`,
idempotency key, canonical payload SHA256 digest, payload byte count, privacy
flags, reconciled field counts, and one embedded validated snapshot.

The standard privacy profile includes host aliases, OS account names, groups,
tags, configured commands, and filesystem paths because those fields are
required by the planned access graph. Raw public-key text is always removed,
even if it was explicitly present in the source snapshot. Unverified comments
are removed by default and require a separate `--include-identity-hints`
choice. Private keys, passwords, keyring values, SSH agent data, and usable
connection credentials have no fields in this contract. A defense-in-depth
content scan additionally rejects PEM/OpenSSH key markers and raw SSH public
key blobs or credential-like assignments smuggled through arbitrary text
fields. The preview also counts authorized-key options and diagnostic text
values, in addition to aliases, accounts, paths, commands, comments, and keys.

The reader rejects unknown envelope fields, trailing JSON, invalid workspaces,
artifacts above 40 MiB, payloads above 32 MiB, digest/idempotency/plan-ID
mismatches, inconsistent privacy flags or preview counts, raw public keys, and
tampered embedded snapshots. Upload remains unimplemented; the artifact is
only a locally reviewable contract candidate.

## Offline workspace history v1

A workspace history is a strict, deterministic local model of immutable
WebPanel ingestion. It embeds one or more validated upload plans belonging to
one workspace, an artifact index, the latest scan ID, and derived transitions.
Exact retries are deduplicated by `scan_id`; the same ID with a different
payload or privacy envelope is rejected. Plans are ordered by parsed RFC3339
completion time and then scan ID. There is no fixed scan-count limit; total
encoded input and output are bounded to 256 MiB.

A transition is comparable only when adjacent snapshots use the same scan
policy and observe the same host aliases; current-account scans must also use
the same SSH account on every completely observed host. Otherwise it records a
reason and no access-edge changes. Hosts with failed or incomplete key
collection are excluded from added/removed edges, and partial coverage carries
an explicit caveat. This prevents missing evidence from being reported as
removal of access. The strict validator recalculates
the complete artifact index, stable history ID, latest pointer, semantic diffs,
coverage changes, exclusions, and caveats, rejecting unknown fields, trailing
JSON, broken embedded plans, or tampered derived values.

## Workspace offboarding history v1

A workspace offboarding history is a strict companion artifact rather than an
extension of the frozen workspace-history v1 contract. It binds validated
offboarding checks to exactly one workspace slug, history ID, latest scan ID,
and canonical scan/time index. Every check's before and after scan must exist
in that index and move forward in the timeline.

Checks are ordered by after-scan position, identity ID, and check ID. Exact
retries are deduplicated; a second distinct check for the same identity and
after scan is rejected as ambiguous. One derived latest row per identity
records its outcome, edge counts, reason codes, after-scan completion time,
and whether that scan is the workspace's current latest scan. A stale outcome
is counted separately and can never contribute to current `complete`,
`still_present`, or `inconclusive` counters.

The strict validator recalculates canonical ordering, latest rows, counters,
and the content-derived offboarding-history ID. The reader rejects unknown
fields, trailing JSON, references outside the bound workspace timeline,
ambiguous identity results, tampering, and artifacts above 256 MiB. The
artifact contains fingerprints and normalized public evidence already present
in its checks, but no raw public keys, credentials, private keys, or passwords.
Building, inspecting, and dashboard rendering are local-only and read-only.

## Workspace ownership history v1

A workspace ownership history is a strict companion to exactly one validated
workspace-history v1 artifact. It embeds one privacy-normalized ownership
review per reviewed scan, while its complete scan index makes missing review
coverage explicit. Reviews must reconcile with the corresponding embedded
workspace snapshot. Exact input retries are deduplicated and a second distinct
review for the same scan is rejected.

The companion derives the latest reviewed scan and marks it current only when
it equals the workspace's `latest_scan_id`. It also derives deterministic
transitions between successive reviews: identity lifecycle records, ownership
claims keyed by fingerprint/identity, and reviewed-key observation/ownership
state. All ordering, counters, transitions, the latest projection, and the
content-derived ownership-history ID are recalculated by the validator.

Embedded reviews always remove unverified `identity_hints` originating from
`authorized_keys` comments. The scan index retains the SHA-256 of each exact
source review so an offboarding check can still be joined to its before/after
inputs without retaining those comments. The strict reader rejects unknown
fields, trailing JSON, conflicting reviews, broken scan references, tampering,
forbidden key/credential material, and artifacts above 256 MiB. Building,
inspecting, and dashboard rendering are local-only and read-only.

## Output and transport rules

Local snapshot, identity map, ownership review, offboarding report/check,
offline upload plan/workspace history/ownership history/offboarding history,
workspace ingestion bundle,
workspace-dashboard HTML, CSV, and graph JSON
files are created
atomically with mode
`0600`. CSV cells
originating from untrusted data are protected against spreadsheet formula
injection.

Merging is an offline artifact operation. It never connects to hosts or uploads
data, and only combines validated, scope-compatible, disjoint observations.

A cloud upload may send only a validated, explicitly selected workspace
ingestion bundle.
It must not gain access to SSH private keys, passwords, agents, keyrings, or
direct server connectivity. The initial append-only ingestion service remains
gated from public production deployment by the criteria in
`sshmgr-cloud-implementation-plan.md`.

## Workspace ingestion bundle v1

The workspace ingestion bundle is the single transport envelope accepted by
the append-only SaaS API. It embeds one validated workspace history and
optional, strictly joined current ownership review, ownership history, and
offboarding history. The builder applies the same evidence joins as the local
dashboard before producing output.

The envelope carries a content-derived `bundle_id`, a stable idempotency key,
the canonical payload size and SHA-256, and separate SHA-256 digests for every
attached artifact. Its preview reports current and timeline observation
counts plus ownership/offboarding coverage. The strict reader recalculates all
of these fields and rejects unknown fields, trailing JSON, broken joins,
tampering, raw public keys, credentials, or files above 512 MiB.

Standalone ownership evidence is embedded without unverified identity hints.
Its source digest is retained because offboarding checks and ownership-history
scan rows bind to the exact original review. This preserves a verifiable join
without transporting authorized-key comments. `cloud bundle-build` and
`cloud bundle-inspect` perform no network activity. `cloud upload` sends the
canonical validated bundle to an explicit HTTPS origin or a named Cloud
profile. `cloud login` and `cloud status` are the other authenticated network
operations. HTTP requires a separate test-only opt-in and a literal loopback
IP on both client and server.

The v1 ingestion endpoint is
`POST /v1/workspaces/{workspace}/bundles`. It requires a workspace-scoped
Bearer token, `Content-Type: application/json`, and an `Idempotency-Key` equal
to the bundle field. The first accepted request returns `201 created`; an
exact retry returns `200 already_exists` with the original immutable receipt.
The service exposes authenticated list and detail GETs but no update or delete
method. Stored records include receipt time and principal ID and are written
append-only with private directories/files. Auth configuration contains only
canonical SHA-256 token digests.

Named Cloud profile v1 metadata is a separate strict mode-`0600` JSON file. It
contains only profile name, API origin, workspace, keyring reference, active
selection, and the test-only loopback opt-in. Bearer values remain in the OS
keyring. A profile login queries
`GET /v1/workspaces/{workspace}/status` before persisting a new token/reference.
The API also provides unauthenticated versioned `/healthz` and storage-aware
`/readyz` probes. Redirects are never followed by authenticated clients.

The local workspace dashboard and access-review CSV are deterministic
projections, not schema-v1 ingestion artifacts. They revalidate the complete
workspace history, derive
current Overview/Findings/Access Graph data only from the latest embedded
snapshot, and derive Timeline data from validated artifact transitions. Their
output is bounded to 256 MiB. HTML escapes untrusted observations and embeds no
JavaScript, remote asset, or remote resource reference. CSV shares the same
validated projection, uses canonical typed rows, and applies spreadsheet
formula protection to every cell.

An optional ownership-review projection is accepted only after both standalone
review validation and a second derivation against the latest embedded snapshot.
The join requires matching scan ID and reconciled observed keys, hosts,
accounts, access counts, identity-map content, claims, lifecycle and findings.
Only unverified comment hints may differ because the upload privacy profile may
remove them. Offboarding rows are read-only evidence grouped by fingerprint so
shared keys do not imply that one specific identity exclusively owns every
private-key copy or access edge.
