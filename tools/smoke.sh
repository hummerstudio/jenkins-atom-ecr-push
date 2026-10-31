#!/usr/bin/env bash
# Pushes real images (an OCI layout, a docker-save tar, a legacy save) at a fake ECR that:
#   * recomputes the SigV4 signature of GetAuthorizationToken from the request as it arrived,
#   * hands out a registry token and refuses anything that does not present it,
#   * verifies every blob against the digest in its URL, and every manifest against the blobs it holds,
#   * stores what it got, so the assertions can open the pushed image and read the file inside it.
# The failure halves are the same server with a defect: a dropped manifest (read-back catches it), an AccessDenied
# token, an expired token, a registry that refuses blobs, a repository that does not exist.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

api=$((24000 + RANDOM % 600)); reg=$((24800 + RANDOM % 600))
state="$(mktemp -d)"; wirelog="$(mktemp)"
start() {
  python3 tools/fake_ecr.py "$api" "$reg" "$state" "$wirelog" "$@" >/dev/null & server=$!
  for _ in $(seq 1 60); do
    curl -s -o /dev/null "http://127.0.0.1:$reg/v2/" && curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$api/" && return 0
    sleep 0.1
  done
  echo "the fake ECR did not start" >&2; exit 1
}
stop() { kill "$server" 2>/dev/null; wait "$server" 2>/dev/null; }
restart() { stop; : >"$wirelog"; start "$@"; }
start; trap 'stop' EXIT

# --- fixtures, built independently of the atom --------------------------------------------------------------------
fx="$(mktemp -d)"
oci_json="$(python3 tools/mk_image.py oci "$fx/oci")"
legacy_json="$(python3 tools/mk_image.py legacy "$fx/legacy")"
python3 tools/mk_image.py oci-tar "$fx/image.tar" >/dev/null
fact() { python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d["platforms"][sys.argv[2]][sys.argv[3]])' "$1" "$2" "$3"; }
m_amd="$(fact "$oci_json" amd64 manifest)"; m_arm="$(fact "$oci_json" arm64 manifest)"
c_amd="$(fact "$oci_json" amd64 config)";  l_amd="$(fact "$oci_json" amd64 layer)"
l_arm="$(fact "$oci_json" arm64 layer)"
c_leg="$(fact "$legacy_json" amd64 config)"; l_leg="$(fact "$legacy_json" amd64 layer)"

# --- helpers ------------------------------------------------------------------------------------------------------
push() {  # push <extra json> [secrets json] [image path]
  local dir secrets image
  dir="$(mktemp -d)"; secrets="${2:-}"; image="${3:-}"
  python3 tools/push_input.py "$dir" "http://127.0.0.1:$api" "http://127.0.0.1:$reg" \
      "123456789012.dkr.ecr.us-east-1.amazonaws.com" "${1:-}" "$image"
  if [ -z "$secrets" ]; then
    secrets='{"accessKey": "AKIAEXAMPLEKEY0001", "secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
  fi
  printf '%s' "$secrets" >"$dir/.secrets.json"
  python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$dir/.secrets.json" || fail "the secrets file is not JSON"
  run "$dir" >"$dir/atom.log" 2>&1
  echo "$dir"
}
ok() { status "$1" | grep -q success || fail "${2:-run}: $(cat "$1/output.json")"; }
bad() { status "$1" | grep -q error || fail "${2:-run} must fail: $(cat "$1/output.json")"; }
error_code() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("errorCode"))' "$1/output.json"; }
say() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("message",""))' "$1/output.json"; }
jget() { python3 -c 'import json,sys
d = json.loads(sys.stdin.read())
for part in sys.argv[1].split("."):
    d = d[int(part)] if part.isdigit() else d[part]
print(json.dumps(d) if isinstance(d, (dict, list)) else d)' "$1"; }
manifest_json() { python3 tools/checkimage.py manifest "$state" "$1" "$2"; }
wire() { python3 tools/wire.py "$wirelog" "$1"; }
count() { wire "$1" | wc -l | tr -d ' '; }
blob_count() { python3 -c 'import os,sys;print(len(os.listdir(sys.argv[1]+"/blobs")))' "$state"; }

# --- the real push: an OCI layout, one platform out of a two-platform list -----------------------------------------
dir=$(push '{"tag": "1.0.0", "platform": "linux/amd64"}' "" "$fx/oci")
ok "$dir" "oci push"
[ "$(output "$dir" digest)" = "$m_amd" ] || fail "digest: $(say "$dir")"
[ "$(output "$dir" blobsUploaded)" = "2" ] || fail "two blobs (config + layer) should be new: $(cat "$dir/output.json")"
[ "$(output "$dir" blobsReused)" = "0" ] || fail "nothing was there yet"
[ "$(output "$dir" verified)" = "true" ] || fail "the push must be read back"
[ "$(output "$dir" tag)" = "1.0.0" ] || fail "tag output"
[ "$(output "$dir" registry)" = "123456789012.dkr.ecr.us-east-1.amazonaws.com" ] || fail "registry output"

# the token call: signed, pointed at the right operation, and asking for this account's registry
[ "$(count 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken')" = "1" ] \
  || fail "the token call carried the wrong X-Amz-Target: $(wire api)"
[ "$(count '"signed_ok": true')" = "1" ] || fail "the signature did not verify: $(wire api)"
[ "$(count 'registryIds')" = "1" ] || fail "the token request must ask for the account's registry"
grep -q '"authorization": "Basic ' "$wirelog" || fail "the registry calls must use the issued token"

# what the registry actually holds
[ "$(python3 tools/checkimage.py blob "$state" "$c_amd")" = "$c_amd" ] || fail "the config blob does not hash to its digest"
[ "$(python3 tools/checkimage.py blob "$state" "$l_amd")" = "$l_amd" ] || fail "the layer blob does not hash to its digest"
stored="$(manifest_json team/app 1.0.0)"
[ "$(printf '%s' "$stored" | jget digest)" = "$m_amd" ] || fail "the tag points at the wrong digest: $stored"
[ "$(printf '%s' "$stored" | jget sha256)" = "$m_amd" ] || fail "the stored manifest is not the one that was sent: $stored"
[ "$(printf '%s' "$stored" | jget json.config.digest)" = "$c_amd" ] \
  || fail "the stored manifest names the wrong config: $stored"
[ "$(python3 tools/checkimage.py layer "$state" "$l_amd")" = '{"app/amd64.txt": "pushed by ecr-push\namd64\n"}' ] \
  || fail "the layer inside the registry is not the layer that was built: $(python3 tools/checkimage.py layer "$state" "$l_amd")"

# --- pushing the same image again uploads nothing -----------------------------------------------------------------
uploads_before="$(count 'blobs/uploads')"
dir=$(push '{"tag": "1.0.1", "platform": "linux/amd64"}' "" "$fx/oci")
ok "$dir" "second push"
[ "$(output "$dir" blobsUploaded)" = "0" ] || fail "a re-push must reuse the blobs: $(cat "$dir/output.json")"
[ "$(output "$dir" blobsReused)" = "2" ] || fail "both blobs were already there"
[ "$(count 'blobs/uploads')" = "$uploads_before" ] || fail "a re-push must not open an upload session: $(wire blobs)"

# --- a different platform out of the same list --------------------------------------------------------------------
dir=$(push '{"tag": "arm", "platform": "linux/arm64"}' "" "$fx/oci")
ok "$dir" "arm64 push"
[ "$(output "$dir" digest)" = "$m_arm" ] || fail "arm64 digest: $(say "$dir")"
[ "$(python3 tools/checkimage.py blob "$state" "$l_arm")" = "$l_arm" ] || fail "the arm64 layer is missing"
[ "$(python3 tools/checkimage.py layer "$state" "$l_arm")" = '{"app/arm64.txt": "pushed by ecr-push\narm64\n"}' ] \
  || fail "the arm64 layer holds the wrong file"

# --- a multi-arch list with no platform is refused, before anything is pushed --------------------------------------
before="$(blob_count)"
dir=$(push '{"tag": "wrong", "platform": ""}' "" "$fx/oci")
bad "$dir" "a multi-platform image without platform"
[ "$(error_code "$dir")" = "40007" ] || fail "that is a USER input problem: $(cat "$dir/output.json")"
grep -q "linux/amd64, linux/arm64" "$dir/output.json" || fail "the message must list what is there: $(say "$dir")"
[ "$(blob_count)" = "$before" ] || fail "a refused input must not upload anything"

# --- docker save tar (an OCI layout in a tarball) -----------------------------------------------------------------
dir=$(push '{"tag": "tar", "platform": "linux/amd64"}' "" "$fx/image.tar")
ok "$dir" "oci tarball push"
[ "$(output "$dir" digest)" = "$m_amd" ] || fail "tar digest: $(say "$dir")"
[ "$(manifest_json team/app tar | jget digest)" = "$m_amd" ] || fail "the tarball's manifest landed under the wrong digest"

# --- legacy docker save: the atom has to write the schema-2 manifest itself ---------------------------------------
dir=$(push '{"tag": "legacy"}' "" "$fx/legacy")
ok "$dir" "legacy save push"
f_legacy="$(manifest_json team/app legacy)"
[ "$(printf '%s' "$f_legacy" | jget json.config.digest)" = "$c_leg" ] \
  || fail "the generated manifest names the wrong config: $f_legacy"
[ "$(printf '%s' "$f_legacy" | jget json.layers.0.digest)" = "$l_leg" ] \
  || fail "the generated manifest names the wrong layer: $f_legacy"
[ "$(printf '%s' "$f_legacy" | jget json.mediaType)" = "application/vnd.docker.distribution.manifest.v2+json" ] \
  || fail "a legacy save pushes a docker manifest: $f_legacy"
[ "$(printf '%s' "$f_legacy" | jget digest)" = "$(printf '%s' "$f_legacy" | jget sha256)" ] \
  || fail "the digest the registry reports is the digest of the manifest it stored: $f_legacy"
[ "$(output "$dir" digest)" = "$(printf '%s' "$f_legacy" | jget digest)" ] \
  || fail "the output digest is what the registry has: $(say "$dir")"
[ "$(python3 tools/checkimage.py layer "$state" "$l_leg")" = '{"app/amd64.txt": "pushed by ecr-push\namd64\n"}' ] \
  || fail "the legacy layer arrived intact"

# --- tags: $BUILD_NUMBER is expanded, an unknown variable is refused ----------------------------------------------
dir=$(push '{"tag": "1.0.$BUILD_NUMBER", "platform": "linux/amd64"}' "" "$fx/oci")
ok "$dir" "expanded tag"
[ "$(output "$dir" tag)" = "1.0.77" ] || fail "the tag must be expanded: $(cat "$dir/output.json")"
manifest_json team/app 1.0.77 >/dev/null || fail "the manifest must be stored under the expanded tag"

before_api="$(count 'GetAuthorizationToken')"
dir=$(push '{"tag": "1.0.$NOT_SET", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "an unset variable in the tag"
grep -q "not set" "$dir/output.json" || fail "the message must name the missing variable: $(say "$dir")"
[ "$(count 'GetAuthorizationToken')" = "$before_api" ] || fail "a bad input must not fetch a token"

dir=$(push '{"tag": "multi", "extraTags": "latest, multi", "platform": "linux/amd64"}' "" "$fx/oci")
ok "$dir" "extra tags"
[ "$(output "$dir" tags)" = "multi,latest" ] || fail "tags output: $(cat "$dir/output.json")"
manifest_json team/app latest >/dev/null || fail "the extra tag must be pushed"

# --- the registry's defects ---------------------------------------------------------------------------------------
restart --drop-manifests
dir=$(push '{"tag": "liar", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "a registry that stores a different manifest"
grep -q "reads back as" "$dir/output.json" || fail "the read-back has to catch it: $(say "$dir")"
[ "$(error_code "$dir")" = "50203" ] || fail "a lying registry is THIRD_PART: $(cat "$dir/output.json")"

restart --wrong-put-digest
dir=$(push '{"tag": "shifted", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "a registry that reports a digest it did not store"
grep -q "the bytes sent hash to" "$dir/output.json" || fail "the message: $(say "$dir")"
[ "$(error_code "$dir")" = "50201" ] || fail "a disagreeing digest is THIRD_PART: $(cat "$dir/output.json")"

restart --deny
dir=$(push '{"tag": "denied", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "AccessDenied on the token"
grep -q "AccessDeniedException" "$dir/output.json" || fail "the AWS error must be passed through: $(say "$dir")"
[ "$(error_code "$dir")" = "40020" ] || fail "a refused credential is the user's problem: $(cat "$dir/output.json")"

restart
dir=$(push '{"tag": "badkey", "platform": "linux/amd64"}' \
          '{"accessKey": "AKIAEXAMPLEKEY0001", "secretKey": "wrong-secret"}' "$fx/oci")
bad "$dir" "a wrong secret key"
[ "$(error_code "$dir")" = "40020" ] || fail "a rejected signature is the user's problem: $(cat "$dir/output.json")"
grep -q "signature" "$dir/output.json" || fail "the message has to say the signature: $(say "$dir")"

restart --expire
dir=$(push '{"tag": "expired", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "an expired registry token"
grep -q "rejected the token" "$dir/output.json" || fail "the message: $(say "$dir")"
[ "$(error_code "$dir")" = "40030" ] || fail "401 at the registry is a credential problem: $(cat "$dir/output.json")"

restart --only-repo=team/other
dir=$(push '{"tag": "norepo", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "a repository that does not exist"
grep -q "no repository team/app" "$dir/output.json" || fail "the message must name the repository: $(say "$dir")"
grep -q "create-repository" "$dir/output.json" || fail "and say what to do: $(say "$dir")"

restart --reject-blobs --hide-blobs
dir=$(push '{"tag": "reject", "platform": "linux/amd64"}' "" "$fx/oci")
bad "$dir" "a registry that refuses the blob"
[ "$(error_code "$dir")" = "50205" ] || fail "a refused upload is THIRD_PART: $(cat "$dir/output.json")"

restart
dir=$(push '{"tag": "missing", "platform": "linux/amd64"}' "" "$fx/does-not-exist")
bad "$dir" "a missing image"
[ "$(error_code "$dir")" = "40007" ] || fail "a missing image path is USER: $(cat "$dir/output.json")"
grep -q "image not found" "$dir/output.json" || fail "the message: $(say "$dir")"

echo "smoke ok: SigV4 token verified independently, OCI/docker-tar/legacy-save pushes, blob dedupe, platform selection," \
     "read-back catches a lying registry, AccessDenied/bad signature/expired token/unknown repo/rejected blob/bad input"
