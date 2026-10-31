#!/usr/bin/env python3
"""Reads the fake registry's storage back: what it actually holds, not what the atom said.

usage:
  checkimage.py blob <state> <digest>            -> sha256 of the stored bytes (must equal the digest)
  checkimage.py manifest <state> <repo> <ref>    -> {"digest":..., "sha256":..., "media":..., "json":...}
  checkimage.py layer <state> <digest>           -> the files inside a layer, with their content
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile


def blob_path(state, digest):
    return os.path.join(state, "blobs", digest.split(":", 1)[1])


def manifest_path(state, repository, reference):
    return os.path.join(state, "manifests", repository.replace("/", "_") + "@@" + reference)


def main():
    command = sys.argv[1]
    if command == "blob":
        state, digest = sys.argv[2:4]
        path = blob_path(state, digest)
        if not os.path.exists(path):
            raise SystemExit("the registry has no blob " + digest)
        raw = open(path, "rb").read()
        print("sha256:" + hashlib.sha256(raw).hexdigest())
    elif command == "manifest":
        state, repository, reference = sys.argv[2:5]
        path = manifest_path(state, repository, reference)
        if not os.path.exists(path):
            raise SystemExit(f"the registry has no manifest {repository}:{reference}")
        raw = open(path, "rb").read()
        print(json.dumps({
            "digest": open(path + ".digest", encoding="utf-8").read().strip(),
            "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "media": open(path + ".media", encoding="utf-8").read().strip(),
            "json": json.loads(raw.decode("utf-8")),
        }, sort_keys=True))
    elif command == "layer":
        state, digest = sys.argv[2:4]
        raw = open(blob_path(state, digest), "rb").read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    files[member.name] = archive.extractfile(member).read().decode("utf-8")
        print(json.dumps(files, sort_keys=True))
    else:
        raise SystemExit("unknown command " + command)


if __name__ == "__main__":
    main()
