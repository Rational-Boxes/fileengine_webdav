# WebDAV Bridge — Development Plan

Status: draft · Last updated: 2026-06-19

This plan addresses correctness and completeness gaps found in the WebDAV
bridge after its migration to the canonical `fileengine` gRPC protocol
(`file_engine_cpp/proto/fileservice.proto`). It is ordered by impact: the
early phases remove data-loss risk and the largest classes of spurious
failures; later phases fill in protocol completeness and hardening.

References below use `file:line` against the current tree (`src/webdav_server.cpp`
unless noted).

## Guiding principles

- **Use the server as the source of truth.** The gRPC core is trusted-access;
  the bridge authenticates via LDAP and passes identity through in `AuthContext`.
  Path/UID resolution, type checks, and metadata belong on the server, not in a
  local cache.
- **Fail loudly, not silently.** No handler should return `2xx` for an operation
  it did not actually perform. Map backend errors to correct WebDAV status codes.
- **RFC 4918 conformance** for status codes, `Depth`, XML escaping, and date
  formats, so standard clients (cadaver, Finder, Windows Explorer, rclone,
  davfs2) interoperate.

## Build / validation note

This environment cannot fully build the bridge (Poco, libpqxx, and LDAP dev
libraries are absent; gRPC/protobuf are present). Proto-facing changes can be
type-checked against generated `fileengine` stubs, but full compilation and the
WebDAV end-to-end suite must run in an environment with the runtime
dependencies installed (see `IMPLEMENTATION.md`). Each phase below lists
acceptance criteria intended to be exercised there.

---

## Phase 0 — Foundation: server-side path resolution

Most downstream bugs stem from the in-memory, root-seeded path cache
(`path_resolver.cpp:14-15`). The migration added a `ResolvePath` RPC
(`grpc_client_->resolvePath`) that resolves an absolute path to a `{uid, type}`
on the server. Adopt it as the primary resolver; keep the cache only as an
optional read-through optimization.

Tasks:
- [ ] Add `PathResolver::resolve(path, tenant, auth)` that calls `ResolvePath`
      and returns `{uid, type, exists}`. Fall back to the in-memory map only on
      transport error.
- [ ] Replace the six `resolvePathToUUID` call sites (`:116, :223, :248, :345,
      :423, :542`) with the new resolver.
- [ ] Eliminate the `"" means root AND means not-found` ambiguity
      (`:224-235, :345-357`): represent root explicitly and distinguish
      "not found" from "is root" using the `exists`/`type` fields.
- [ ] Bound or remove the local cache (currently unbounded, never evicted, lost
      on restart). If kept, add a max size + TTL and treat it as best-effort.

Acceptance:
- Direct `GET`/`PUT`/`DELETE`/`PROPFIND` on a deep path that was never walked
  from root succeeds (no spurious `404`/`409`).
- Restarting the bridge does not change resolution behavior.

---

## Phase 1 — Critical: implement COPY and MOVE (data-loss fix)

`handleCopy`/`handleMove` (`:716-804`) authenticate and return `201` **without
any gRPC call** — the operation silently does nothing. The wrapper already
exposes `copyFile`, `moveFile`, and `renameFile`.

Tasks:
- [ ] `handleCopy`: resolve source UID; resolve destination parent UID + name;
      call `copyFile(source_uid, destination_parent_uid)`. If the destination
      basename differs from the source, follow with `renameFile`.
- [ ] `handleMove`: same resolution, then `moveFile`; if only the basename
      changes within the same parent, use `renameFile` instead.
- [ ] Honor the `Overwrite: T|F` header (RFC 4918 §9.8/§9.9): `F` + existing
      destination ⇒ `412 Precondition Failed`.
- [ ] Correct status codes: `201 Created` for a new destination, `204 No
      Content` when overwriting an existing one; `409` when the destination
      parent is missing.
- [ ] Update/repair the path cache for both source and destination.
- [ ] Reject or correctly handle cross-tenant `Destination` hosts.

Acceptance:
- `MOVE`/`COPY` actually relocate/duplicate the resource on the backend;
  source state after `MOVE` is gone; `Overwrite: F` is respected.

---

## Phase 2 — Major: correct PROPFIND

`handlePropfind` (`:499-670`) always calls `ListDirectory` regardless of type,
ignores `Depth`, and masks failures as a fake root collection (`:578-603`).

Tasks:
- [ ] Resolve the target and branch on type (`GetFileInfo`/`ResolvePath`):
  - File ⇒ emit a single `<D:response>` with file properties, never a
    `<D:collection/>`.
  - Collection ⇒ emit the collection plus children.
- [ ] Honor the `Depth` header:
  - `0` ⇒ the target resource only.
  - `1` ⇒ target + immediate children (current intent).
  - `infinity` ⇒ either implement recursive walk or return `403` with
    `<DAV:propfind-finite-depth/>` (RFC 4918 §9.1).
- [ ] Remove the "return an empty root collection on failure" path (`:578-603`);
      map backend errors to real status: not-found ⇒ `404`, permission ⇒ `403`,
      transport ⇒ `503`.
- [ ] Populate the target collection's own properties from `GetFileInfo` instead
      of hard-coded values (`:621-625`).
- [ ] (Optional) Parse the PROPFIND request body to support `allprop`,
      `propname`, and specific `<D:prop>` selections; today a fixed set is always
      returned.

Acceptance:
- PROPFIND on a file returns a non-collection resource with correct length/dates.
- `Depth: 0` on a collection returns exactly one response element.
- Permission/not-found produce correct status, not a fake `200`.

---

## Phase 3 — Major: well-formed PROPFIND output

Tasks:
- [ ] Add an `xmlEscape()` helper and apply it to every text node
      (`displayname`, and any names) — `:618, :633, :639`.
- [ ] URL-encode `href` path segments using the existing `urlEncode()`
      (`utils.cpp:51`) — `:636`.
- [ ] Emit RFC 1123 for `getlastmodified` and ISO 8601 for `creationdate`
      from the entry timestamps, replacing the raw-epoch+`Z` output
      (`:595-596, :624-625, :655-656`). Use Poco `DateTimeFormatter`.
- [ ] Only emit `getcontentlength` for non-collections; omit for collections.

Acceptance:
- A directory containing a file named `a & b<c>.txt` produces valid, parseable
  XML and the client lists it correctly.
- `getlastmodified` parses as a date in standard clients.

---

## Phase 4 — Complete the remaining methods

### 4a. PROPPATCH (`:672-714`)
Currently returns `424` for everything.
- [ ] Map settable/dead properties to backend metadata
      (`SetMetadata`/`DeleteMetadata`) and return `200` per property in the
      `multistatus`.
- [ ] For protected/live properties, return `403 Forbidden` per RFC, not `424`.

### 4b. LOCK / UNLOCK (`:806-840`) and `DAV` advertisement (`:850`)
The current LOCK returns a static `dummy-lock-token`, tracks nothing, and
skips authentication; `OPTIONS` advertises `DAV: 1, 2` (class 2 = locking).
Choose one:
- [ ] **Option A (recommended near-term):** advertise `DAV: 1` only and return
      `501`/`405` for LOCK/UNLOCK — honest about no locking.
- [ ] **Option B:** implement a real in-memory (or backend-backed) lock table
      with unique tokens, timeouts, `Depth`, owner, and `If`-header validation
      on write methods; require authentication for LOCK/UNLOCK.

### 4c. GET/HEAD (`:84-164`)
- [ ] Branch `HEAD` to send headers only (no body); today HEAD runs a full
      `ReadFile` and writes content (`:163`).
- [ ] Handle `Range` requests (advertised via `Accept-Ranges: bytes` at `:852`)
      or stop advertising ranges.
- [ ] `GET` on a collection ⇒ `405` (or an index listing), not a `ReadFile`
      that 500s.
- [ ] Set `Content-Type` from stored metadata when available, instead of always
      `application/octet-stream` (`:160`).

### 4d. PUT status (`:286`)
- [ ] Return `201 Created` only for newly created resources; `204 No Content`
      when overwriting an existing one (RFC 4918 §9.7).

Acceptance:
- PROPPATCH of a custom property round-trips via PROPFIND.
- `OPTIONS` `DAV` header matches actual capability.
- `HEAD` returns headers with no body and no wasted backend read.

---

## Phase 5 — Streaming & large files

GET buffers the whole file in `ReadFileResponse.data`; PUT buffers the whole
body via `copyToString` (`:200`). Memory scales with file size.
- [ ] Use `StreamFileDownload`/`StreamFileUpload` for bodies over a threshold,
      streaming chunks to/from the socket.
- [ ] Add the corresponding streaming methods to `GRPCClientWrapper`.

Acceptance: a multi-GB upload/download completes without proportional memory
growth.

---

## Phase 6 — Security & hardening

- [ ] **Remove credential logging** (`:884, :892, :902`): never log the base64
      blob or the decoded `user:password`. Redact at all log levels.
- [ ] Reconsider `Access-Control-Allow-Origin: *` on an authenticated endpoint
      (`:856`); scope to configured origins or drop CORS.
- [ ] Remove dead Digest-auth helpers (`utils.cpp:71-120`) or finish wiring
      Digest into `authenticateUser`.
- [ ] Review the tenant heuristic (`utils.cpp:140-143`): the hyphen-truncation
      rule turns `tenant-dev.example.com` into `tenant`. Make the
      subdomain→tenant mapping explicit/configurable.

---

## Phase 7 — Tests & CI

- [ ] Re-enable the unit test target in `CMakeLists.txt` (currently commented
      out) after making the wrapper methods mockable (the mocks use `(override)`
      against non-virtual methods, and `MockPathResolver` references a removed
      2-arg constructor). Either introduce a small virtual interface for the
      wrapper or adjust the mocks.
- [ ] Add a WebDAV conformance pass using the existing scripts
      (`webdav_validation_suite.sh`, `test_webdav.sh`) plus `litmus` if
      available, run against a live `file_engine_cpp` server.
- [ ] Cover the regression cases: file vs. collection PROPFIND, `Depth` values,
      special-character names, MOVE/COPY with `Overwrite`, deep-path access
      without prior walk.

---

## Tracking checklist (high level)

| # | Item | Phase | Severity |
|---|------|-------|----------|
| 1 | COPY/MOVE are no-op stubs | 1 | Critical (data loss) |
| 2 | PROPFIND mistreats files; masks errors | 2 | Major |
| 3 | `Depth` header ignored | 2 | Major |
| 4 | Malformed PROPFIND dates | 3 | Major |
| 5 | No XML-escaping / URL-encoding | 3 | Major |
| 6 | Cache-only path resolution (no `ResolvePath`) | 0 | Major |
| 7 | `""` overloads root vs. not-found | 0 | Major |
| 8 | Fake LOCK but advertises `DAV: 2` | 4b | Incomplete |
| 9 | PROPPATCH always fails | 4a | Incomplete |
| 10 | Digest helpers unused | 6 | Dead code |
| 11 | HEAD reads & writes full body | 4c | Bug |
| 12 | GET on dir 500s; no Range | 4c | Bug |
| 13 | PUT overwrite returns 201 | 4d | Bug |
| 14 | Whole-file buffering | 5 | Scalability |
| 15 | Tenant hyphen truncation | 6 | Bug |
| 16 | Credentials logged at debug | 6 | Security |

Out of scope / verified OK: the gRPC wrapper and the `fileengine` migration are
correct; the LDAP bind performs a real password bind with no bypass
(`ldap_authenticator.cpp:94-136`).
