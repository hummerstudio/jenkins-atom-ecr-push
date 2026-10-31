#!/usr/bin/env python3
"""Builds the images the smoke pushes: a real OCI layout and a real legacy docker-save tarball.

They are built here, in another language and from the spec, so that the atom's reading of a saved image is checked
against bytes it did not write. Every digest printed is computed from the file on disk.

usage: mk_image.py <mode> <dir>        mode = oci | oci-tar | legacy
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile

HELLO = "pushed by ecr-push\n"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 1700000000
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def layer_for(arch):
    """One gzipped layer whose file name differs per architecture, so picking the wrong one is visible."""
    tar = tar_bytes({f"app/{arch}.txt": f"{HELLO}".encode("utf-8") + arch.encode("utf-8") + b"\n"})
    return gzip.compress(tar, mtime=0), tar


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def build_oci(root):
    blobs = os.path.join(root, "blobs", "sha256")
    write(os.path.join(root, "oci-layout"), json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
    entries = []
    facts = {}
    for arch in ("amd64", "arm64"):
        gz, raw = layer_for(arch)
        layer_digest = write_blob(blobs, gz)
        config = json.dumps({
            "architecture": arch,
            "os": "linux",
            "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},
            "rootfs": {"type": "layers", "diff_ids": [digest(raw)]},
            "history": [{"created_by": "mkdir app"}],
        }, sort_keys=True).encode()
        config_digest = write_blob(blobs, config)
        manifest = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "size": len(config), "digest": config_digest},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "size": len(gz), "digest": layer_digest}],
        }, sort_keys=True).encode()
        manifest_digest = write_blob(blobs, manifest)
        entries.append({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": manifest_digest, "size": len(manifest),
                        "platform": {"os": "linux", "architecture": arch}})
        facts[arch] = {"manifest": manifest_digest, "config": config_digest,
                       "layer": layer_digest, "layer_size": len(gz), "file": f"app/{arch}.txt"}
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries}
    write(os.path.join(root, "index.json"), json.dumps(index, sort_keys=True).encode())
    return facts


def write_blob(blobs, data):
    d = digest(data)
    write(os.path.join(blobs, d.split(":", 1)[1]), data)
    return d


def build_legacy(root):
    """The old docker save shape: manifest.json, a config file named after its own hash, plain layer tars."""
    os.makedirs(root, exist_ok=True)
    layer, raw = layer_for("amd64")
    layer_path = os.path.join(root, "layerdir", "layer.tar")
    write(layer_path, raw)
    config = json.dumps({"architecture": "amd64", "os": "linux",
                         "rootfs": {"type": "layers", "diff_ids": [digest(raw)]}}).encode()
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    write(os.path.join(root, config_name), config)
    manifest = [{"Config": config_name, "RepoTags": ["legacy/app:1.0"], "Layers": ["layerdir/layer.tar"]}]
    write(os.path.join(root, "manifest.json"), json.dumps(manifest).encode())
    return {"manifest": None, "config": digest(config), "layer": digest(raw), "layer_size": len(raw),
            "file": "app/amd64.txt"}


def tarball(source, target):
    with tarfile.open(target, "w") as archive:
        for base, _, files in os.walk(source):
            for name in files:
                full = os.path.join(base, name)
                archive.add(full, arcname=os.path.relpath(full, source), recursive=False)


def main():
    mode, target = sys.argv[1], sys.argv[2]
    if mode == "oci":
        facts = build_oci(target)
        print(json.dumps({"root": target, "platforms": facts}))
    elif mode == "oci-tar":
        staging = target + ".d"
        facts = build_oci(staging)
        tarball(staging, target)
        print(json.dumps({"archive": target, "platforms": facts}))
    elif mode == "legacy":
        facts = build_legacy(target)
        print(json.dumps({"root": target, "platforms": {"amd64": facts}}))
    else:
        raise SystemExit("unknown mode " + mode)


if __name__ == "__main__":
    main()
