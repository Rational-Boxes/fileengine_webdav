#!/bin/bash
#
# End-to-end test for the WebDAV bridge: exercises the full lifecycle including
# MOVE (rename + relocate) and COPY (cross-parent + same-parent duplicate).
#
# The WebDAV door no longer accepts the LDAP directory password (PROPOSAL §14/§15
# hardening): the ONLY credential is a backend-issued `key:secret` service
# credential, AND an active login session must exist (the bridge's session gate,
# checked against Redis presence written at login). So this test first performs a
# real login — email-2FA when the tenant requires it, with the code captured from
# MailHog, or a direct token when MFA is off — mints a `webdav`-scoped service
# credential, and drives every WebDAV verb with that key:secret. The credential is
# revoked on exit. (The `key:secret` model is separately covered end-to-end by
# scripts/test_e2e_service_cred.sh.)
#
# Environment (nothing secret is committed):
#   WEBDAV_URL   WebDAV base URL        (default http://localhost:8088)
#   API_URL      http_bridge base URL   (default http://localhost:8090)  [login]
#   IDM_URL      ldap_manager base URL  (default http://localhost:8093)  [service-credentials]
#   MAILHOG_URL  MailHog base URL       (default http://localhost:8025)  [email-2FA code]
#   WEBDAV_USER  login (uid or email)   (default testuser@rationalboxes.com)
#   WEBDAV_PASS  login password         (required — used to LOG IN; never sent to WebDAV)
#   WEBDAV_HOST  optional Host header   (selects the tenant; default: none)
#
# Usage:  WEBDAV_PASS='...' ./test_webdav.sh
set -u

WEBDAV_URL="${WEBDAV_URL:-http://localhost:8088}"
API_URL="${API_URL:-http://localhost:8090}"
IDM_URL="${IDM_URL:-http://localhost:8093}"
MAILHOG_URL="${MAILHOG_URL:-http://localhost:8025}"
WEBDAV_USER="${WEBDAV_USER:-testuser@rationalboxes.com}"
WEBDAV_PASS="${WEBDAV_PASS:-}"
WEBDAV_HOST="${WEBDAV_HOST:-}"

if [ -z "$WEBDAV_PASS" ]; then
  echo "ERROR: set WEBDAV_PASS (the login password; used to obtain a session + service credential)." >&2
  exit 2
fi

# Minimal JSON field extractor (stdlib only).
jget() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

# When a tenant is selected via Host, apply it to the login too so the session +
# credential land in the same tenant the WebDAV requests target.
LOGIN_HOSTH=()
[ -n "$WEBDAV_HOST" ] && LOGIN_HOSTH=(-H "Host: ${WEBDAV_HOST}")

# Log in and echo a session bearer. Handles both MFA-required tenants (password ->
# emailed code via MailHog -> completion) and MFA-off tenants (token returned by
# the first call). The completed login writes the WebDAV session presence the
# bridge's session gate requires.
login() {
  local resp tok mfatok code
  resp=$(curl -s -u "${WEBDAV_USER}:${WEBDAV_PASS}" "${LOGIN_HOSTH[@]}" -X POST "$API_URL/v1/auth/token")
  tok=$(echo "$resp" | jget token)
  if [ -n "$tok" ]; then echo "$tok"; return 0; fi
  mfatok=$(echo "$resp" | jget mfa_token)
  [ -n "$mfatok" ] || { echo "login: no token and no MFA challenge ($resp)" >&2; return 1; }
  curl -s -X DELETE "$MAILHOG_URL/api/v1/messages" >/dev/null
  curl -s -X POST "$API_URL/v1/auth/2fa" -H 'Content-Type: application/json' \
    -d "{\"mfa_token\":\"$mfatok\",\"action\":\"send\",\"method\":\"email\"}" >/dev/null
  sleep 1
  code=$(curl -s "$MAILHOG_URL/api/v2/messages" | python3 -c "
import sys,json,re,quopri
items=json.load(sys.stdin).get('items',[])
b=quopri.decodestring(items[0]['Content']['Body']).decode('utf-8','ignore') if items else ''
print((re.findall(r'\b(\d{6})\b', b) or [''])[0])")
  [ -n "$code" ] || { echo "login: no email 2FA code found in MailHog" >&2; return 1; }
  tok=$(curl -s -X POST "$API_URL/v1/auth/2fa" -H 'Content-Type: application/json' \
    -d "{\"mfa_token\":\"$mfatok\",\"method\":\"email\",\"code\":\"$code\"}" | jget token)
  [ -n "$tok" ] || { echo "login: 2FA completion returned no token" >&2; return 1; }
  echo "$tok"
}

echo "== WebDAV E2E: authenticating as ${WEBDAV_USER} =="
TOKEN="$(login)" || { echo "ERROR: login failed for ${WEBDAV_USER}." >&2; exit 1; }

# Mint a webdav-scoped service credential (the only credential the door accepts).
CRED=$(curl -s -H "Authorization: Bearer $TOKEN" "${LOGIN_HOSTH[@]}" -H 'Content-Type: application/json' \
       -d '{"label":"webdav-e2e","scopes":["webdav"]}' "$IDM_URL/v1/me/service-credentials")
KEY=$(echo "$CRED" | jget key_id); SEC=$(echo "$CRED" | jget secret)
[ -n "$KEY" ] && [ -n "$SEC" ] || { echo "ERROR: could not mint a webdav service credential ($CRED)." >&2; exit 1; }
echo "   minted service credential ${KEY} (session-gated as ${WEBDAV_USER})"

# Revoke the credential on any exit so repeated runs don't accumulate creds.
cleanup() {
  [ -n "${KEY:-}" ] && curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" \
    -X DELETE "$IDM_URL/v1/me/service-credentials/$KEY" 2>/dev/null
}
trap cleanup EXIT

# All WebDAV requests authenticate with the key:secret, never the password.
AUTH=(-u "${KEY}:${SEC}")
HOSTH=()
[ -n "$WEBDAV_HOST" ] && HOSTH=(-H "Host: ${WEBDAV_HOST}")

# Base URL to use inside Destination: headers for COPY/MOVE. The bridge's
# cross-host guard (security fix M4) requires the Destination host to match the
# request Host header, so when WEBDAV_HOST selects a tenant we must build the
# Destination with that same host (preserving scheme + port), not the raw
# WEBDAV_URL host.
DEST_URL="$WEBDAV_URL"
if [ -n "$WEBDAV_HOST" ]; then
  _proto="${WEBDAV_URL%%://*}"
  _rest="${WEBDAV_URL#*://}"; _hostport="${_rest%%/*}"
  _port=""; case "$_hostport" in *:*) _port=":${_hostport##*:}";; esac
  DEST_URL="${_proto}://${WEBDAV_HOST}${_port}"
fi

BASE="/e2e_webdav_test"          # working dir created/removed by this test
pass=0; fail=0

# --- helpers ---------------------------------------------------------------
# req METHOD PATH EXPECTED [extra curl args...]
req() {
  local method="$1" path="$2" expected="$3"; shift 3
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "${AUTH[@]}" "${HOSTH[@]}" "$@" "${WEBDAV_URL}${path}")
  if [ "$code" = "$expected" ]; then
    echo "  PASS  $method $path -> $code"; pass=$((pass+1))
  else
    echo "  FAIL  $method $path -> $code (expected $expected)"; fail=$((fail+1))
  fi
}

propfind() {  # PATH  -> prints displaynames
  curl -s -X PROPFIND -H "Depth: 1" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}$1" \
    | grep -oE '<D:displayname>[^<]*</D:displayname>' | sed -E 's,</?D:displayname>,,g'
}

assert_listing() {  # PATH  NAME  present|absent
  local names; names="$(propfind "$1")"
  if echo "$names" | grep -qxF "$2"; then
    [ "$3" = present ] && { echo "  PASS  '$2' present in $1"; pass=$((pass+1)); } \
                       || { echo "  FAIL  '$2' should be absent in $1"; fail=$((fail+1)); }
  else
    [ "$3" = absent ]  && { echo "  PASS  '$2' absent from $1"; pass=$((pass+1)); } \
                       || { echo "  FAIL  '$2' should be present in $1"; fail=$((fail+1)); }
  fi
}

dest() { echo "-HDestination: ${DEST_URL}$1"; }   # build Destination header arg

# assert_body PATH EXPECTED  — GET the path and compare the exact body.
assert_body() {
  local got; got="$(curl -s "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}$1")"
  if [ "$got" = "$2" ]; then echo "  PASS  GET $1 body == '$2'"; pass=$((pass+1));
  else echo "  FAIL  GET $1 body '$got' != '$2'"; fail=$((fail+1)); fi
}

# lock_token PATH  — LOCK the path, echo the opaque token from the Lock-Token
# response header (RFC 4918 §9.10.1). Empty output means the header was missing.
lock_token() {
  local body='<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>e2e</D:href></D:owner></D:lockinfo>'
  curl -s -D - -o /dev/null -X LOCK "${AUTH[@]}" "${HOSTH[@]}" \
    -H "Timeout: Second-300" -H "Content-Type: application/xml" --data "$body" "${WEBDAV_URL}$1" \
    | awk 'tolower($1)=="lock-token:"{print $2}' | tr -d '\r'
}

# prop_value PATH PROP  — PROPFIND Depth:0 and echo the text of <D:PROP>.
prop_value() {
  curl -s -X PROPFIND -H "Depth: 0" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}$1" \
    | grep -oiE "<D:$2>[^<]*</D:$2>" | sed -E "s,</?D:$2>,,g" | head -1
}

echo "== WebDAV E2E ($WEBDAV_URL as $WEBDAV_USER) =="

# Clean slate, then scaffold.
curl -s -o /dev/null -X DELETE "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}"
req MKCOL "${BASE}"          201
req MKCOL "${BASE}/dirA"     201
echo "hello e2e" | req PUT "${BASE}/dirA/file.txt" 201 --data-binary @-
req GET   "${BASE}/dirA/file.txt" 200
assert_listing "${BASE}/dirA" "file.txt" present

echo "-- MOVE: rename a file (same parent) --"
req MOVE "${BASE}/dirA/file.txt" 201 -H "Destination: ${DEST_URL}${BASE}/dirA/renamed.txt"
assert_listing "${BASE}/dirA" "renamed.txt" present
assert_listing "${BASE}/dirA" "file.txt"    absent

echo "-- MOVE: rename a folder (same parent) --"
req MOVE "${BASE}/dirA" 201 -H "Destination: ${DEST_URL}${BASE}/dirB"
assert_listing "${BASE}" "dirB"  present
assert_listing "${BASE}" "dirA"  absent

echo "-- MOVE: relocate a folder (different parent) --"
req MKCOL "${BASE}/dest" 201
req MOVE  "${BASE}/dirB" 201 -H "Destination: ${DEST_URL}${BASE}/dest/dirB"
assert_listing "${BASE}/dest" "dirB" present
assert_listing "${BASE}"      "dirB" absent

echo "-- COPY: file to a different parent (same name) --"
req COPY "${BASE}/dest/dirB/renamed.txt" 201 -H "Destination: ${DEST_URL}${BASE}/copy.txt"
assert_listing "${BASE}" "copy.txt" present
assert_listing "${BASE}/dest/dirB" "renamed.txt" present   # source still there

echo "-- COPY: same-parent duplicate (different name) --"
req COPY "${BASE}/copy.txt" 201 -H "Destination: ${DEST_URL}${BASE}/copy-dup.txt"
assert_listing "${BASE}" "copy.txt"     present            # source preserved
assert_listing "${BASE}" "copy-dup.txt" present

echo "-- RENDITIONS: hidden children of a file --"
req PUT "${BASE}/doc.txt"          201 --data-binary "primary content"
# A rendition is a child of the file (parent = the file's path).
req PUT "${BASE}/doc.txt/alt.pdf"  201 --data-binary "alternate-format rendition"
# The rendition must NOT appear in the parent directory listing...
assert_listing "${BASE}" "doc.txt" present
assert_listing "${BASE}" "alt.pdf" absent
# ...nor when listing the file itself (PROPFIND Depth:1 on the file).
assert_listing "${BASE}/doc.txt" "alt.pdf" absent
# ...and the file must still present as a file, never a collection.
fxml=$(curl -s -X PROPFIND -H "Depth: 1" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}/doc.txt")
if echo "$fxml" | grep -q '<D:collection/>'; then
  echo "  FAIL  file with renditions advertised as a collection"; fail=$((fail+1))
else
  echo "  PASS  file with renditions is not a collection"; pass=$((pass+1))
fi

# Mirrors the REST bridge's "create -> PUT v1/v2/v3 -> versions" scenario
# (http_bridge tests/test_e2e.sh) so the same lifecycle is exercised on both
# doors. Over WebDAV a "new revision" is simply another PUT to the same path; the
# core appends a version each time. First PUT creates (201); each later PUT
# overwrites an existing resource (204 No Content, RFC 4918 §9.7.1) — matching the
# REST PUT /v1/files/{uid}/content status.
echo "-- REVISIONS: create then write new revisions to the same path --"
req PUT "${BASE}/revs.txt" 201 --data-binary "revision one"
assert_body "${BASE}/revs.txt" "revision one"
req PUT "${BASE}/revs.txt" 204 --data-binary "revision two"
req PUT "${BASE}/revs.txt" 204 --data-binary "revision three"
assert_body "${BASE}/revs.txt" "revision three"   # GET returns the latest revision

# Regression guard for the "file changed on disk" editor loop: an unchanged file
# MUST report a STABLE getlastmodified/creationdate across reads. The core once
# stamped now() on every Stat, so each PROPFIND showed a newer mtime and editors
# (Bluefish, gedit, ...) believed the file kept changing on disk. Timestamps are
# now derived from the version-name / DB columns, so they only move on a real
# write.
echo "-- TIMESTAMP STABILITY: unchanged file reports a constant mtime --"
lm1="$(prop_value "${BASE}/revs.txt" getlastmodified)"
cd1="$(prop_value "${BASE}/revs.txt" creationdate)"
sleep 2
lm2="$(prop_value "${BASE}/revs.txt" getlastmodified)"
cd2="$(prop_value "${BASE}/revs.txt" creationdate)"
[ -n "$lm1" ] && [ "$lm1" = "$lm2" ] && { echo "  PASS  getlastmodified stable across reads ($lm1)"; pass=$((pass+1)); } \
                                     || { echo "  FAIL  getlastmodified changed: '$lm1' -> '$lm2'"; fail=$((fail+1)); }
[ -n "$cd1" ] && [ "$cd1" = "$cd2" ] && { echo "  PASS  creationdate stable across reads ($cd1)"; pass=$((pass+1)); } \
                                     || { echo "  FAIL  creationdate changed: '$cd1' -> '$cd2'"; fail=$((fail+1)); }
# ...but a real revision MUST advance getlastmodified (genuine changes still show).
sleep 1; curl -s -o /dev/null "${AUTH[@]}" "${HOSTH[@]}" -X PUT --data-binary "revision four" "${WEBDAV_URL}${BASE}/revs.txt"
lm3="$(prop_value "${BASE}/revs.txt" getlastmodified)"
[ -n "$lm3" ] && [ "$lm3" != "$lm2" ] && { echo "  PASS  getlastmodified advances on a real write ($lm2 -> $lm3)"; pass=$((pass+1)); } \
                                      || { echo "  FAIL  getlastmodified did not change after a write ($lm2 -> $lm3)"; fail=$((fail+1)); }

# Regression guard for the "changed on disk when saving a new version" bug:
# GVfs-backed editors (Bluefish, gedit) track a file by its ETag. The validator
# MUST be (a) identical across PUT/GET/HEAD/PROPFIND for the same content so a
# cached etag matches a later query, (b) stable across reads, and (c) returned by
# the PUT of a new version so the client adopts it instead of seeing an
# unexplained change. Missing/inconsistent ETags were the "changed on disk" cause.
echo "-- ETAG: consistent validator across surfaces + across a save --"
hdr_etag() { curl -s -D - -o /dev/null "${AUTH[@]}" "${HOSTH[@]}" "$@" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r'; }
pf_etag()  { curl -s -X PROPFIND -H "Depth: 0" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}$1" \
             | grep -oiE '<D:getetag>[^<]*</D:getetag>' | sed -E 's,</?D:getetag>,,g' | head -1; }
EF="${BASE}/etagged.txt"
eput=$(hdr_etag -X PUT --data-binary "etag v1" "${WEBDAV_URL}${EF}")
eget=$(hdr_etag -X GET "${WEBDAV_URL}${EF}")
ehead=$(hdr_etag -I "${WEBDAV_URL}${EF}")
epf=$(pf_etag "${EF}")
[ -n "$eput" ] && { echo "  PASS  PUT returns an ETag ($eput)"; pass=$((pass+1)); } || { echo "  FAIL  PUT returned no ETag"; fail=$((fail+1)); }
{ [ "$eput" = "$eget" ] && [ "$eget" = "$ehead" ] && [ "$ehead" = "$epf" ]; } \
  && { echo "  PASS  ETag identical across PUT/GET/HEAD/PROPFIND"; pass=$((pass+1)); } \
  || { echo "  FAIL  ETag differs (PUT=$eput GET=$eget HEAD=$ehead PROPFIND=$epf)"; fail=$((fail+1)); }
er1=$(hdr_etag -X GET "${WEBDAV_URL}${EF}"); sleep 2; er2=$(hdr_etag -X GET "${WEBDAV_URL}${EF}")
[ -n "$er1" ] && [ "$er1" = "$er2" ] && { echo "  PASS  ETag stable across reads"; pass=$((pass+1)); } \
                                      || { echo "  FAIL  ETag changed across reads ($er1 -> $er2)"; fail=$((fail+1)); }
sleep 1; eput2=$(hdr_etag -X PUT --data-binary "etag v2 is longer" "${WEBDAV_URL}${EF}")
{ [ -n "$eput2" ] && [ "$eput2" != "$eput" ]; } \
  && { echo "  PASS  saving a new version returns a NEW ETag ($eput -> $eput2)"; pass=$((pass+1)); } \
  || { echo "  FAIL  new version did not change the ETag ($eput -> $eput2)"; fail=$((fail+1)); }
eget2=$(hdr_etag -X GET "${WEBDAV_URL}${EF}")
[ "$eput2" = "$eget2" ] && { echo "  PASS  post-save GET ETag matches the PUT response"; pass=$((pass+1)); } \
                        || { echo "  FAIL  post-save GET ETag ($eget2) != PUT ETag ($eput2)"; fail=$((fail+1)); }

# Regression guard for the "IO error on first save of a new file" bug: editors
# (macOS Finder, Windows, GNOME/KDE, ...) LOCK the target before the first PUT,
# and abort with an IO error if the LOCK response omits the Lock-Token header
# (RFC 4918 §9.10.1). Exercise the full LOCK -> PUT(If) -> UNLOCK save handshake,
# for both a brand-new file and a subsequent revision.
echo "-- LOCK/PUT/UNLOCK: editor save handshake (new file + revision) --"
for round in 1 2; do
  tok="$(lock_token "${BASE}/locked.txt")"
  if [ -n "$tok" ]; then echo "  PASS  LOCK round $round returned a Lock-Token"; pass=$((pass+1));
  else echo "  FAIL  LOCK round $round returned no Lock-Token header"; fail=$((fail+1)); fi
  # First save creates (201); the second is a new revision over the now-existing
  # resource (204). Either is a success for the save handshake.
  exp=201; [ "$round" = 2 ] && exp=204
  req PUT "${BASE}/locked.txt" "$exp" -H "If: (${tok})" --data-binary "locked save $round"
  req UNLOCK "${BASE}/locked.txt" 204 -H "Lock-Token: ${tok}"
done
assert_body "${BASE}/locked.txt" "locked save 2"
# LOCK is a write-class verb: it must authenticate (no anonymous locks) and an
# UNLOCK with no Lock-Token header is malformed (RFC 4918 §9.11 -> 400).
lock_noauth=$(curl -s -o /dev/null -w '%{http_code}' -X LOCK "${HOSTH[@]}" \
  -H "Content-Type: application/xml" --data '<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>' \
  "${WEBDAV_URL}${BASE}/locked.txt")
[ "$lock_noauth" = 401 ] && { echo "  PASS  anonymous LOCK -> 401"; pass=$((pass+1)); } \
                         || { echo "  FAIL  anonymous LOCK -> $lock_noauth (expected 401)"; fail=$((fail+1)); }
req UNLOCK "${BASE}/locked.txt" 400   # missing Lock-Token header

# Streaming/chunking: a body larger than the per-request/gRPC-message transaction
# size must upload via chunked streaming (never buffered whole) and round-trip
# byte-for-byte. Mirrors the REST bridge's large streaming-upload assertion.
echo "-- STREAMING: large file (8 MiB) chunked upload + download round-trip --"
big_src="$(mktemp)"; big_dl="$(mktemp)"
head -c $((8*1024*1024)) /dev/urandom > "$big_src"
req PUT "${BASE}/big.bin" 201 --data-binary @"$big_src"
curl -s "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}/big.bin" -o "$big_dl"
if cmp -s "$big_src" "$big_dl"; then
  echo "  PASS  8 MiB round-trip is byte-identical ($(wc -c <"$big_dl") bytes)"; pass=$((pass+1))
else
  echo "  FAIL  8 MiB round-trip mismatch (src $(wc -c <"$big_src") vs dl $(wc -c <"$big_dl"))"; fail=$((fail+1))
fi
rm -f "$big_src" "$big_dl"

echo "-- DELETE: recursive removal of a non-empty collection --"
req DELETE "${BASE}" 204
# Verify the whole tree is gone (PROPFIND on the base now 404s).
base_code=$(curl -s -o /dev/null -w '%{http_code}' -X PROPFIND -H "Depth: 0" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}")
if [ "$base_code" = "404" ]; then echo "  PASS  ${BASE} fully removed (404)"; pass=$((pass+1));
else echo "  FAIL  ${BASE} still present (PROPFIND $base_code)"; fail=$((fail+1)); fi

echo "== results: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
