#!/usr/bin/env python3
"""A fake ECR: the token API and the registry, with the checks ECR really does.

Two servers in one process:

  * the ECR JSON API (SigV4-signed ``GetAuthorizationToken``) -- the signature is *recomputed here*, from the request as
    it arrived, with the same rules AWS uses (canonical request, derived signing key, constant-time compare). A wrong
    secret key, a wrong region, a replayed body or an unsigned ``x-amz-target`` all come back 403, exactly like AWS.
  * the registry (Docker Registry V2) -- Basic auth with the token it just handed out, and it verifies what it is given:
    a blob's bytes must hash to the digest in the URL, and a manifest may only name blobs it actually holds. It stores
    under ``--state`` so the test can read the image back off disk and open it.

Flags exist to be the *bad* server: ``--deny`` answers the token call with AccessDenied, ``--drop-manifests`` answers
201 and stores one byte more than it got (the read-back has to catch that), ``--expire`` refuses the token at the
registry door.

usage: fake_ecr.py <api-port> <registry-port> <state-dir> <log> [flags]
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACCESS_KEY = "AKIAEXAMPLEKEY0001"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
REGION = "us-east-1"
SERVICE = "ecr"
TARGET = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"

lock = threading.Lock()
log_path = None
state = None
flags = set()
repository_password = None
issued_token = None


def log(record):
    with lock:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def allowed(repository):
    for flag in flags:
        if flag.startswith("only-repo="):
            return repository == flag.split("=", 1)[1]
    return True


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


# --------------------------------------------------------------------------- SigV4, recomputed independently

def canonical_query(pairs):
    encoded = []
    for name, value in pairs:
        encoded.append((urllib.parse.quote(name, safe="-_.~"), urllib.parse.quote(value, safe="-_.~")))
    encoded.sort()
    return "&".join(f"{name}={value}" for name, value in encoded)


def verify_signature(method, path, query, headers, body):
    """Recompute the signature from the request as it arrived. Returns (ok, reason)."""
    auth = headers.get("authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return False, "not a SigV4 Authorization header"
    fields = {}
    for part in auth[len("AWS4-HMAC-SHA256 "):].split(","):
        key, _, value = part.strip().partition("=")
        fields[key] = value
    credential = fields.get("Credential", "")
    signed_headers = fields.get("SignedHeaders", "")
    signature = fields.get("Signature", "")
    bits = credential.split("/")
    if len(bits) != 5:
        return False, "malformed Credential " + credential
    key_id, date_stamp, region, service, terminator = bits
    if key_id != ACCESS_KEY:
        return False, "unknown access key " + key_id
    if region != REGION or service != SERVICE:
        return False, f"scope is {region}/{service}, expected {REGION}/{SERVICE}"
    amz_date = headers.get("x-amz-date", "")
    if not amz_date.startswith(date_stamp):
        return False, f"x-amz-date {amz_date} does not match the credential date {date_stamp}"
    names = signed_headers.split(";")
    for required in ("host", "x-amz-date"):
        if required not in names:
            return False, "the signature does not cover " + required

    lines = []
    for name in names:
        if name not in headers:
            return False, "signed header " + name + " is missing from the request"
        lines.append(f"{name}:{headers[name].strip()}")
    canonical_headers = "\n".join(lines) + "\n"
    payload_hash = sha256_hex(body)
    canonical_request = "\n".join([
        method,
        path or "/",
        query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        sha256_hex(canonical_request.encode("utf-8")),
    ])
    key = hmac_sha256(("AWS4" + SECRET_KEY).encode("utf-8"), date_stamp)
    key = hmac_sha256(key, region)
    key = hmac_sha256(key, service)
    key = hmac_sha256(key, "aws4_request")
    expected = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "signature mismatch (recomputed " + expected[:16] + ", got " + signature[:16] + ")"
    return True, "ok"


# --------------------------------------------------------------------------- ECR JSON API

class EcrApi(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        parsed = urllib.parse.urlsplit(self.path)
        headers = {name.lower(): value for name, value in self.headers.items()}
        ok, reason = verify_signature("POST", parsed.path, canonical_query(
            urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)), headers, body)
        target = headers.get("x-amz-target", "")
        log({"server": "api", "method": "POST", "path": self.path, "target": target,
             "body": body.decode("utf-8", "replace"), "signature": reason, "signed_ok": ok,
             "content_sha256": sha256_hex(body)})

        if target != TARGET:
            return self.reply(400, {"__type": "com.amazon.coral.service#UnknownOperationException",
                                    "message": "unexpected X-Amz-Target: " + target})
        if not ok:
            return self.reply(403, {"__type": "com.amazon.coral.service#InvalidSignatureException",
                                    "message": reason})
        if "deny" in flags:
            return self.reply(400, {"__type": "com.amazonaws.ecr#AccessDeniedException",
                                    "message": "User is not authorized to perform ecr:GetAuthorizationToken"})

        token = base64.b64encode(f"AWS:{repository_password}".encode("utf-8")).decode("ascii")
        globals()["issued_token"] = token
        self.reply(200, {"authorizationData": [{
            "authorizationToken": token,
            "expiresAt": "2030-01-01T00:00:00+00:00",
            "proxyEndpoint": f"http://127.0.0.1:{self.server.registry_port}",
        }]})

    def reply(self, status, doc):
        body = json.dumps(doc).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --------------------------------------------------------------------------- registry V2

def blob_path(digest):
    return os.path.join(state, "blobs", digest.split(":", 1)[1])


def manifest_path(repository, reference):
    return os.path.join(state, "manifests", repository.replace("/", "_") + "@@" + reference)


class Registry(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # -- plumbing ------------------------------------------------------------------------------------------------
    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def allowed(self, repository):
        for flag in flags:
            if flag.startswith("only-repo="):
                return repository == flag.split("=", 1)[1]
        return True

    def authorized(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            self.fail(401, "UNAUTHORIZED", "no Basic credentials")
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
        except Exception:
            self.fail(401, "UNAUTHORIZED", "credentials are not base64")
            return False
        if "expire" in flags:
            self.fail(401, "UNAUTHORIZED", "the token has expired")
            return False
        expected = f"AWS:{repository_password}"
        if not hmac.compare_digest(decoded, expected):
            self.fail(401, "UNAUTHORIZED", "wrong registry password")
            return False
        return True

    def fail(self, status, code, detail):
        payload = {"errors": [{"code": code, "message": detail}]}
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="fake-ecr"')
        self.end_headers()
        if self.command != "HEAD":
            # HTTP forbids a body on HEAD. Writing one leaves bytes in the connection, and the client then reads
            # them as the start of the next response: the symptom is a status line glued to a JSON error.
            self.wfile.write(raw)

    def note(self, method):
        log({"server": "registry", "method": method, "path": self.path,
             "authorization": self.headers.get("Authorization", "")[:12],
             "content_type": self.headers.get("Content-Type", "")})

    def route(self):
        """-> (repository, marker, tail): the repository may contain slashes, so it cannot be counted in."""
        parsed = urllib.parse.urlsplit(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        rest = parts[1:]
        for marker in ("blobs", "manifests"):
            if marker in rest:
                index = rest.index(marker)
                return parsed, "/".join(rest[:index]), marker, rest[index + 1:]
        return parsed, "", "", rest

    # -- endpoints -----------------------------------------------------------------------------------------------
    def do_GET(self):
        parsed, repository, marker, tail = self.route()
        self.note("GET")
        if parsed.path.rstrip("/") == "/v2":
            return self.reply(200, b"{}", {"Docker-Distribution-API-Version": "registry/2.0"})
        return self.fail(404, "NOT_FOUND", "not a fake")

    def do_HEAD(self):
        parsed, repository, marker, tail = self.route()
        self.note("HEAD")
        if not self.authorized():
            return
        if not allowed(repository):
            return self.fail(404, "NAME_UNKNOWN", "repository name not known to registry: " + repository)
        if marker == "blobs" and len(tail) == 1:
            digest = tail[0]
            path = blob_path(digest)
            if os.path.exists(path) and "hide-blobs" not in flags:
                size = os.path.getsize(path)
                self.send_response(200)
                self.send_header("Docker-Content-Digest", digest)
                self.send_header("Content-Length", "0")
                self.send_header("X-Blob-Size", str(size))
                self.end_headers()
                return
            return self.fail(404, "BLOB_UNKNOWN", "no such blob " + digest)
        if marker == "manifests" and len(tail) == 1:
            reference = tail[0]
            path = manifest_path(repository, reference)
            if os.path.exists(path):
                digest = open(path + ".digest", encoding="utf-8").read().strip()
                self.send_response(200)
                self.send_header("Docker-Content-Digest", digest)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self.fail(404, "MANIFEST_UNKNOWN", "no such manifest " + reference)
        return self.fail(404, "NOT_FOUND", "not a fake")

    def do_POST(self):
        parsed, repository, marker, tail = self.route()
        self.body()
        self.note("POST")
        if not self.authorized():
            return
        if not allowed(repository):
            return self.fail(404, "NAME_UNKNOWN", "repository name not known to registry: " + repository)
        if marker == "blobs" and tail == ["uploads"]:
            location = f"/v2/{repository}/blobs/uploads/{uuid.uuid4()}"
            self.send_response(202)
            self.send_header("Location", location)
            self.send_header("Docker-Upload-UUID", location.rsplit("/", 1)[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return self.fail(404, "NOT_FOUND", "not a fake")

    def do_PUT(self):
        parsed, repository, marker, tail = self.route()
        data = self.body()
        self.note("PUT")
        if not self.authorized():
            return
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if not allowed(repository):
            return self.fail(404, "NAME_UNKNOWN", "repository name not known to registry: " + repository)
        if marker == "blobs" and len(tail) == 2 and tail[0] == "uploads":
            digest = query.get("digest", "")
            actual = "sha256:" + sha256_hex(data)
            log({"server": "registry", "event": "blob-upload", "digest": digest, "actual": actual,
                 "size": len(data)})
            if digest != actual:
                return self.fail(400, "DIGEST_INVALID", f"the body hashes to {actual}, not {digest}")
            if "reject-blobs" in flags:
                return self.fail(400, "DIGEST_INVALID", "the registry refuses this blob")
            os.makedirs(os.path.join(state, "blobs"), exist_ok=True)
            with open(blob_path(digest), "wb") as handle:
                handle.write(data)
            self.send_response(201)
            self.send_header("Docker-Content-Digest", digest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if marker == "manifests" and len(tail) == 1:
            reference = tail[0]
            try:
                doc = json.loads(data.decode("utf-8"))
            except Exception:
                return self.fail(400, "MANIFEST_INVALID", "not JSON")
            missing = []
            for descriptor in [doc.get("config", {})] + list(doc.get("layers", [])):
                digest = descriptor.get("digest")
                if not digest or not os.path.exists(blob_path(digest)):
                    missing.append(str(digest))
            if missing:
                return self.fail(400, "MANIFEST_BLOB_UNKNOWN",
                                 "the manifest names blobs that were never uploaded: " + ", ".join(missing))
            # --drop-manifests: answer 201 with the digest of what it received, but store one byte more. The lie is
            # only visible to a client that asks the tag what it resolves to afterwards.
            stored = data + (b" " if "drop-manifests" in flags else b"")
            claimed = data + (b"x" if "wrong-put-digest" in flags else b"")
            digest = "sha256:" + sha256_hex(claimed)
            stored_digest = "sha256:" + sha256_hex(stored)
            os.makedirs(os.path.join(state, "manifests"), exist_ok=True)
            with open(manifest_path(repository, reference), "wb") as handle:
                handle.write(stored)
            with open(manifest_path(repository, reference) + ".digest", "w", encoding="utf-8") as handle:
                handle.write(stored_digest)
            with open(manifest_path(repository, reference) + ".media", "w", encoding="utf-8") as handle:
                handle.write(self.headers.get("Content-Type", ""))
            log({"server": "registry", "event": "manifest", "repository": repository,
                 "reference": reference, "digest": digest, "stored_digest": stored_digest,
                 "mediaType": self.headers.get("Content-Type", ""), "size": len(stored)})
            self.send_response(201)
            self.send_header("Docker-Content-Digest", digest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return self.fail(404, "NOT_FOUND", "not a fake")

    def reply(self, status, body, headers):
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    global log_path, state, flags, repository_password
    api_port, registry_port, state_dir, log_file = (
        int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4])
    flags = {argument.lstrip("-") for argument in sys.argv[5:]}
    log_path = log_file
    state = state_dir
    os.makedirs(os.path.join(state, "blobs"), exist_ok=True)
    os.makedirs(os.path.join(state, "manifests"), exist_ok=True)
    repository_password = secrets.token_hex(12)

    api = ThreadingHTTPServer(("127.0.0.1", api_port), EcrApi)
    api.registry_port = registry_port
    registry = ThreadingHTTPServer(("127.0.0.1", registry_port), Registry)
    for server in (api, registry):
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"fake ecr ready: api={api_port} registry={registry_port}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
