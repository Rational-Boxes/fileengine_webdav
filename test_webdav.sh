#!/bin/bash
#
# End-to-end test for the WebDAV bridge: exercises the full lifecycle including
# MOVE (rename + relocate) and COPY (cross-parent + same-parent duplicate).
#
# Credentials are taken from the environment (nothing secret is committed):
#   WEBDAV_URL   base URL              (default http://localhost:8088)
#   WEBDAV_USER  login (uid or email)  (default testuser@rationalboxes.com)
#   WEBDAV_PASS  password              (required)
#   WEBDAV_HOST  optional Host header  (selects the tenant; default: none)
#
# Usage:  WEBDAV_PASS='...' ./test_webdav.sh
set -u

WEBDAV_URL="${WEBDAV_URL:-http://localhost:8088}"
WEBDAV_USER="${WEBDAV_USER:-testuser@rationalboxes.com}"
WEBDAV_PASS="${WEBDAV_PASS:-}"
WEBDAV_HOST="${WEBDAV_HOST:-}"

if [ -z "$WEBDAV_PASS" ]; then
  echo "ERROR: set WEBDAV_PASS (and optionally WEBDAV_USER/WEBDAV_URL/WEBDAV_HOST)." >&2
  exit 2
fi

AUTH=(-u "${WEBDAV_USER}:${WEBDAV_PASS}")
HOSTH=()
[ -n "$WEBDAV_HOST" ] && HOSTH=(-H "Host: ${WEBDAV_HOST}")

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

dest() { echo "-HDestination: ${WEBDAV_URL}$1"; }   # build Destination header arg

echo "== WebDAV E2E ($WEBDAV_URL as $WEBDAV_USER) =="

# Clean slate, then scaffold.
curl -s -o /dev/null -X DELETE "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}"
req MKCOL "${BASE}"          201
req MKCOL "${BASE}/dirA"     201
echo "hello e2e" | req PUT "${BASE}/dirA/file.txt" 201 --data-binary @-
req GET   "${BASE}/dirA/file.txt" 200
assert_listing "${BASE}/dirA" "file.txt" present

echo "-- MOVE: rename a file (same parent) --"
req MOVE "${BASE}/dirA/file.txt" 201 -H "Destination: ${WEBDAV_URL}${BASE}/dirA/renamed.txt"
assert_listing "${BASE}/dirA" "renamed.txt" present
assert_listing "${BASE}/dirA" "file.txt"    absent

echo "-- MOVE: rename a folder (same parent) --"
req MOVE "${BASE}/dirA" 201 -H "Destination: ${WEBDAV_URL}${BASE}/dirB"
assert_listing "${BASE}" "dirB"  present
assert_listing "${BASE}" "dirA"  absent

echo "-- MOVE: relocate a folder (different parent) --"
req MKCOL "${BASE}/dest" 201
req MOVE  "${BASE}/dirB" 201 -H "Destination: ${WEBDAV_URL}${BASE}/dest/dirB"
assert_listing "${BASE}/dest" "dirB" present
assert_listing "${BASE}"      "dirB" absent

echo "-- COPY: file to a different parent (same name) --"
req COPY "${BASE}/dest/dirB/renamed.txt" 201 -H "Destination: ${WEBDAV_URL}${BASE}/copy.txt"
assert_listing "${BASE}" "copy.txt" present
assert_listing "${BASE}/dest/dirB" "renamed.txt" present   # source still there

echo "-- COPY: same-parent duplicate (different name) --"
req COPY "${BASE}/copy.txt" 201 -H "Destination: ${WEBDAV_URL}${BASE}/copy-dup.txt"
assert_listing "${BASE}" "copy.txt"     present            # source preserved
assert_listing "${BASE}" "copy-dup.txt" present

echo "-- DELETE: recursive removal of a non-empty collection --"
req DELETE "${BASE}" 204
# Verify the whole tree is gone (PROPFIND on the base now 404s).
base_code=$(curl -s -o /dev/null -w '%{http_code}' -X PROPFIND -H "Depth: 0" "${AUTH[@]}" "${HOSTH[@]}" "${WEBDAV_URL}${BASE}")
if [ "$base_code" = "404" ]; then echo "  PASS  ${BASE} fully removed (404)"; pass=$((pass+1));
else echo "  FAIL  ${BASE} still present (PROPFIND $base_code)"; fail=$((fail+1)); fi

echo "== results: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
