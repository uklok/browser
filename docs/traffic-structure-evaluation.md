# Traffic-to-structure provider evaluation

Decision record for [uklok/browser#19](https://github.com/uklok/browser/issues/19): evaluating which parts of raw-traffic to API-structure derivation belong in UKLOK versus external tooling before [#12](https://github.com/uklok/browser/issues/12) builds the exploration-session core.

## Decision summary

| Surface | Decision | Summary |
| --- | --- | --- |
| REST / OpenAPI inference | **KEEP** internal (~230 lines) | None of `mitmproxy2swagger 0.15.0`, `mitm2openapi v0.8.1`, or `traffic2openapi v0.4.2` preserves UKLOK's canonical-origin, query-merging, observed-only schema, opaque-path, and leak-free guarantees without UKLOK re-owning path clustering and HAR splitting anyway. |
| GraphQL document parsing | **ADOPT** `graphql-core 3.3.x` (follow-up capsule) | Eliminates regex misparses on comments, string literals, and invalid documents with zero transitive dependencies; UKLOK keeps transport-variant, batch, persisted-query, and fail-closed secret semantics. |
| Interchange boundary | **ADAPT** HAR 1.2 as projection only | Standard HAR 1.2 works as an optional sanitized export projection paired with a sidecar provenance index, never as the authoritative capture IR. |
| #12 exploration core interface | **ADAPT** `TrafficStructureProvider` | #12 consumes [structure_provider.py](file:///home/antigravity/uklok/browser/automations/_runtime/structure_provider.py) (`TrafficStructureProvider`, `ProviderMetadata`, `default_structure_provider`) instead of private `operations._*` internals. |

## Comparison fixtures

All candidates were exercised against UKLOK's actual fixtures rather than synthetic toy examples:

1. [tests/operations-reading.py](file:///home/antigravity/uklok/browser/tests/operations-reading.py) — 7 API calls across 3 steps (`step_a`..`step_c`), redirect hop replacement (`r1`), static/HTML/orphan/human-tab filtering, 7 lifted secrets, missing response body (`nobody`), and GraphQL variable/literal secrets.
2. [tests/operations-hardening.py](file:///home/antigravity/uklok/browser/tests/operations-hardening.py) and [automations/reading_honeypot/](file:///home/antigravity/uklok/browser/automations/reading_honeypot/expectations.json) — canonical-origin boundaries (`http` vs `https`, host case, default ports), opaque challenge segments (`/challenge/jStkcFiTKsVzcqdhcpWMPdYC`), stable English multi-char segments (`/acknowledgements`, `/GetCurrentUserProfile`), `/bucket/1000..1019`, form-urlencoded + malformed JSON + `204` empty body, multi-call query/body merging, GraphQL transport variants, and 50,000-call scale reconciliation.

Each external candidate was fed an equivalent sanitized HAR 1.2 projection produced from UKLOK's assembled API calls and lifted secrets.

## Measured comparison

### 1. Semantic fidelity

| Capability | UKLOK `operations.py` | `mitmproxy2swagger 0.15.0` | `mitm2openapi v0.8.1` | `traffic2openapi v0.4.2` |
| --- | --- | --- | --- | --- |
| Endpoint grouping & canonical origin | Scheme + normalized host/port + templated path; HTTP != HTTPS | Single `--api-prefix` string match (case-, scheme-, port-sensitive); drops `API.reading.test` and `:80` | Single `--prefix` string match (case-, scheme-, port-sensitive); drops `API.reading.test` and `:80` | Origin-blind (`METHOD + pathTemplate` only); merges `http://` and `https://` and invents invalid `https://port.reading.test:80` server |
| Path parameterization | UUID, numeric >=4, hex, mixed ID, entropy (`_identifier`); preserves `/acknowledgements` and `/GetCurrentUserProfile` | `[0-9]+` regex by default; misses opaque/UUID/hex tokens | Unattended `discover` collapses `/bucket/1000` + `/users/1001` into `/{id1}/{id2}` and `/resource-00..39/items/*` into `/{id1}/items/{id2}`; `--include-patterns "**"` matches concrete paths before templates | `base64IdPattern` (`^[A-Za-z0-9_-]{16,}$`) falsely templates `/acknowledgements` and `/GetCurrentUserProfile` into `/{id}` |
| Query parameter merging | Unions all observed query params and tracks `x-uklok-observed-on-all-calls` | First-write-wins (`set_key_if_not_exists`); drops `?sort=asc` after `?page=1` | Returns early at `has_operation` (`builder.rs:604`); drops `?sort=asc` after `?page=1` | Merges all observed query params across calls |
| Schema inference & repeated calls | Merges properties, records `x-uklok-observed-present` & `x-uklok-observed-on-all`, OpenAPI 3.1.0 JSON | First-write-wins; drops later response schemas | Wraps differing response objects in `oneOf` variants; OpenAPI 3.0.3 YAML (`nullable: true` for null) | Merges properties cleanly, OpenAPI 3.0/3.1/3.2 JSON |
| Optional vs required claims | Never promotes single-run presence to `required` | Does not emit `required` | Marks `requestBody.required: true` | Promotes observed-on-all fields to `required: [...]` |
| Non-JSON content types | JSON only (REST) + GraphQL variants | JSON, MessagePack, `application/x-www-form-urlencoded` | JSON, MessagePack, `application/x-www-form-urlencoded` | JSON only (`form-urlencoded` becomes empty `type: object`) |
| Malformed / missing bodies & statuses | Missing body stays `unobserved`; malformed JSON ignored; status preserved | Malformed JSON `{not json` misparsed as `form-urlencoded`; `204` and `400` without body emitted as `'200'` | Malformed JSON ignored; `204`/`400` preserved; missing status `0` silently emitted as `'200'` | Malformed JSON emitted as `schema: {"type": "object"}`; **fails entire batch** on status `< 100` (`field status: must be >= 100`) |
| GraphQL operation identity | Preserves GET, JSON POST, `application/graphql`, batches, persisted queries, unparsed state | Collapses all operations into one `POST /graphql` | Collapses `GetThing` and `UpdateThing` into one `POST /graphql` with `oneOf` | Collapses all operations into one `POST /graphql` |

### 2. Security

- **Raw secret avoidance**: None of the three external tools detects cookie/query/body/GraphQL-argument secrets structurally across a browser session. UKLOK's `Secrets` lifting (`_collect`) must still run *before* any projection.
- **Placeholder preservation & JSON key safety**: Passing raw string-replaced HAR caused `POST /items` (whose header carried `Authorization: Bearer Authorization` and whose response body was `{"Authorization": "published-field-value"}`) to corrupt the JSON property name into `"${UKLOK_SECRET_002}"`. `project_run_to_har` in [structure_provider.py](file:///home/antigravity/uklok/browser/automations/_runtime/structure_provider.py) solves this by redacting JSON scalar values without mutating property keys.
- **Example re-materialization**:
  - `mitm2openapi` accepts `--redact-fields` / `--redact-patterns` and redacted `resp-secret-xyz` / `form-secret-password` when explicitly configured, **but** its `requestBody` example store (`builder.rs:653, 747`) ignores `--max-examples 0` and still writes `requestBody.content.*.examples` (proved on `POST /items` and `/graphql`). Without redaction flags, `make_example_name` also uses the first string value (such as `form_secret_password`) as the YAML example key name.
  - `traffic2openapi` embeds raw observed `"example"` / `"examples"` values in parameters and schemas and filters out `authorization`/`cookie` headers by default (`pkg/har/converter.go`), erasing UKLOK auth placeholders.
  - `mitmproxy2swagger` omits examples unless `-e` is passed, and explicitly warns `-e`/`-hd` leak secrets.
- **Fail-closed verifier**: Under any provider, UKLOK's `verify_reading` must remain the final post-generation leak gate.

### 3. Determinism and versioning

| Tool | Byte-equal on reordered equivalent calls (`eq_a` vs `eq_b`) | Reason |
| --- | --- | --- |
| UKLOK `operations.py` | **Yes** (semantic + per-artifact deterministic JSON with `sort_keys=True`) | Deterministic grouping, sorted keys, no concrete IDs/secrets in derived artifacts |
| `mitm2openapi v0.8.1` | **No** with defaults (`--max-examples 5` or auto-discovered concrete paths); **Yes** only with pre-curated templates + `--max-examples 0` (response side) | Default output depends on first-seen concrete path and example order |
| `mitmproxy2swagger 0.15.0` | **No** | `paths` order follows HAR arrival order; `info.title` embeds input filename |
| `traffic2openapi v0.4.2` | **No** | `"example"` / `"examples"` and `"servers"` order depend on observation order |

The provider boundary records `provider`, `provider_version`, `provider_config_hash`, `input_projection_hash`, and `output_hash` in `ProviderMetadata` ([structure_provider.py](file:///home/antigravity/uklok/browser/automations/_runtime/structure_provider.py)).

### 4. Operational cost (50,000-call scale fixture)

Input: 50,000 calls across 40 endpoint groups, 4 steps, and 4 ~1 MB response bodies (`35.66 MB` HAR projection). Measured on this host (`linux/amd64`, Python 3.11.2 / 3.12.16):

| Tool / Mode | Wall time | Peak RSS | Notes |
| --- | --- | --- | --- |
| UKLOK `operations.py` | `16.90 s` | `343.3 MB` | Includes CDP assembly, checkpoint attribution, secret lifting, double verification, atomic staging; pure stdlib Python |
| `mitm2openapi v0.8.1` (`discover`) | `0.51 s` | `22.0 MB` | Emits 50,001 templates including over-collapsed `/{id1}/items/{id2}` |
| `mitm2openapi v0.8.1` (`generate`, `--include-patterns "**"`) | Timed out (`>54 s` CPU) | — | Compiles 50,001 regexes and runs ~2.5B linear regex matches |
| `mitm2openapi v0.8.1` (`generate`, 40 pre-curated templates, `--max-examples 0`) | `2.52 s` | `62.6 MB` | Fast only after UKLOK pre-curates the 40 templates |
| `traffic2openapi v0.4.2` (`convert har`) | `0.65 s` | `168.0 MB` | Upstream `go.mod` pulls `omnistorage` -> AWS/GCS/`google.golang.org/api`/gRPC (failed `go build` without stripping cloud storage backends) |
| `traffic2openapi v0.4.2` (`generate`) | Failed on raw (`status < 100`); `1.49 s` with synthetic `status=200` | `135.9 MB` | Fails entire batch if any call has missing status `0` |
| `mitmproxy2swagger 0.15.0` (pass 1 + pass 2 curated) | `35.89 s` + `9.70 s` = `45.59 s` | `85.9 MB` / `55.9 MB` | Requires Python `>= 3.12` (unavailable in Debian 12 base Python 3.11) and 47 packages (`mitmproxy`, `cryptography`, `flask`, etc.) |

### 5. Ownership cost audit of `operations.py`

Inspecting all 57 top-level definitions (1,563 lines) in [operations.py](file:///home/antigravity/uklok/browser/automations/_runtime/operations.py):

- **~1,330 lines (~85%) are UKLOK-intrinsic** and would still exist under any external REST provider:
  - `_assemble` + CDP `redirectHasExtraInfo` + `response_body` correlation + checkpoint/target ownership (232 lines)
  - `_canonical_host`, `_canonical_origin`, `_identities`, `_group` (75 lines)
  - `Secrets`, `_collect`, `_credential_rules`, `_dependency_names` (212 lines)
  - `_provenance`, `_body_evidence`, `_endpoint_records`, `_graphql` (126 lines)
  - Atomic staging, `_generation_id`, `_reader_fingerprint`, `verify_reading`, `derive_operations` (685+ lines)
- **~230 lines (~15%) are generic infrastructure**:
  - `_entropy`, `_identifier`, `_template` (60 lines) — already outperforms all three external tools on UKLOK's opaque/English-word fixtures
  - `_api` (15 lines)
  - `_schema`, `_merge_schema`, `_openapi` (101 lines) — simpler, more accurate (OpenAPI 3.1.0, no `oneOf` explosion, no false `required`), and zero-dependency compared to integrating and working around an external binary
  - `_gql_descriptor` + regexes (60 lines) — **the one clear generic liability** where an external parser (`graphql-core`) strictly improves correctness.

Replacing ~160 lines of clean stdlib Python REST schema/OpenAPI construction with an external CLI while re-implementing path clustering, origin splitting, query merging, and post-generation sanitization increases complexity rather than reducing ownership.

## Interchange boundary findings (HAR 1.2)

`project_run_to_har` in [structure_provider.py](file:///home/antigravity/uklok/browser/automations/_runtime/structure_provider.py) establishes a clean sanitized, target/step-scoped HAR 1.2 projection for interoperability. However, HAR 1.2 cannot faithfully carry six UKLOK semantics without non-standard extensions (`HAR_UNREPRESENTABLE_GAPS`):

1. `checkpoint_and_move_ownership` — checkpoint/Move/Branch attribution (`owner`, `opening_seq`, `last_seq`, `owner_candidates`);
2. `redirect_hop_count_and_opening_hop_lineage` — redirect counts and pre-redirect opening hop attribution on one assembled call;
3. `body_acquisition_state_unobserved_vs_oversized_vs_loading_failed` — HAR omits `content.text` identically for `204` empty responses, `oversized` captures, `loading_failed`, and `unobserved` bodies;
4. `graphql_batch_entry_indexing` — splitting one HTTP JSON-array exchange into per-entry GraphQL operations matched by `entry_index`;
5. `origin_scoped_credential_rules_and_secret_store_lineage` — mapping placeholders back to `traffic/secrets.env` and canonical-origin rules;
6. `observed_only_non_completeness_and_presence_metadata` — distinguishing observed presence from server-level requiredness.

Therefore, HAR 1.2 remains an optional export/interop projection paired with an external provenance index, not UKLOK's authoritative IR.

## GraphQL-core proof

Pressure-testing `graphql-core 3.3.2` (`graphql.parse`, `visit`, `print_ast`, MIT, pure Python, 0 transitive dependencies) against all UKLOK GraphQL fixtures proved:

- **All 8 required forms preserved**: GET `?query=`, JSON POST, raw `application/graphql`, JSON batches (including repeated operation names matched by `entry_index`), named operations (including multi-operation documents selected by `operationName`), anonymous shorthand/unnamed operations (canonicalized via AST literal replacement + `print_ast` hash), named and hash-only persisted queries, and explicit `unparsed` state (`graphql-document-not-understood` on `GraphQLError`).
- **Three real regex bugs eliminated**:
  1. `# query FakeOp { x }\nquery RealOp { thing { id } }` (without `operationName`): regex misidentified `FakeOp`; AST resolved `RealOp`.
  2. `{ thing(note: "query FakeName") { id } }`: regex misidentified `FakeName` inside a string literal; AST hashed as `anonymous-...`.
  3. `"not valid { graphql !!!"`: regex marked `parsed: true` because `{` appeared; AST rejected syntax as `unparsed`.
- **Security nuance preserved**: `print_ast` strips GraphQL `# ...` comments from the emitted document. When adopting `graphql-core`, UKLOK must retain a fail-closed raw-comment leak check (or scan raw query comments during `verify_reading`) so the `reading_honeypot` `graphql_comment` trap still fails closed rather than silently discarding a secret that appeared in capture.

## Responsibility matrix

| Responsibility | UKLOK | External REST provider | `graphql-core` | Decision | Reason |
| --- | --- | --- | --- | --- | --- |
| Raw CDP capture, target/session scope, redirect assembly, late body correlation | Owner | None | None | **KEEP** | Depends directly on Chrome CDP envelopes, `redirectHasExtraInfo`, and checkpoint sequence ranges. |
| Typed checkpoint / Move / Branch attribution | Owner | None | None | **KEEP** | Intrinsic UKLOK causal domain model; external tools have no checkpoint/Move concept. |
| Canonical origin identity (`scheme + normalized host[:port]`) | Owner | Rejected (`mitm2openapi` prefix-sensitive; `traffic2openapi` origin-blind) | None | **KEEP** | Authority and credential boundary cannot collapse `http` vs `https` or case/port equivalents. |
| Secret lifting, origin-scoped rules, generation-coherent fail-closed leak gate | Owner | Inadequate (`--max-examples 0` leak in `mitm2openapi`; no structural detection) | AST literal/arg walking helper | **KEEP** | Security trust boundary must never depend on external redaction flags. |
| Generic path templating (`_identifier`) | Owner | Rejected (over-collapse in `mitm2openapi` & false positives in `traffic2openapi`) | None | **KEEP** | 60-line internal implementation already handles opaque tokens without collapsing English resource names. |
| Observed-only JSON schema merge & OpenAPI 3.1.0 emission | Owner | Rejected (`oneOf` explosion, false `required`, `status < 100` failure, missing query merge) | None | **KEEP** | ~101 lines of stdlib Python avoids external binary packaging, pre-curation loops, and semantic regressions. |
| GraphQL transport variants, batch index pairing, persisted-query & observed-only model | Owner | None | None | **KEEP** | Specific to HTTP transport wrappers and observed-only non-completeness guarantees. |
| GraphQL document lexing, AST parsing, operation/type extraction, literal canonicalization | Remove regex (`GQL_*`) | None | Owner (`3.3.x`) | **ADOPT** | Eliminates regex bugs with MIT license and zero transitive dependencies (execute in a dedicated capsule). |
| Sanitized HAR 1.2 export projection | Adapter (`project_run_to_har`) | Consumer | None | **ADAPT** | Useful interop view for external consumers, paired with sidecar provenance for HAR-unrepresentable metadata. |
| Derived-structure interface for #12 | Owner (`TrafficStructureProvider`) | Pluggable behind protocol | Behind provider | **ADAPT** | Decouples #12 exploration core from `operations.py` internals and records provider/config/input/output hashes. |

## Follow-up capsules

1. **GraphQL-core adoption capsule (separate PR)**: replace regex-based GraphQL parsing in [operations.py](file:///home/antigravity/uklok/browser/automations/_runtime/operations.py) with `graphql-core 3.3.x` while preserving raw-comment fail-closed verification and all [tests/operations-hardening.py](file:///home/antigravity/uklok/browser/tests/operations-hardening.py) / [reading_honeypot](file:///home/antigravity/uklok/browser/automations/reading_honeypot/expectations.json) invariants.
2. **#12 exploration core integration**: depend strictly on [structure_provider.py](file:///home/antigravity/uklok/browser/automations/_runtime/structure_provider.py) (`TrafficStructureProvider` / `default_structure_provider`) and never import private `operations._*` helpers.
3. **Optional 50k-call performance pass**: cache `_identities(call)` once per assembled call inside `operations.py` if 50k-call derivation latency (`16.9s` today) becomes user-visible.
