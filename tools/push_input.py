#!/usr/bin/env python3
"""Writes the input.json a build step would get, so the smoke only says what it is changing.

usage: push_input.py <dir> <api-url> <registry-endpoint> <registry-host> <extra-json> [image]
"""
import json
import sys

directory, api, endpoint, host, extra = sys.argv[1:6]
image = sys.argv[6] if len(sys.argv) > 6 else ""
data = {
    "registry": host,
    "registryEndpoint": endpoint,
    "ecrEndpoint": api,
    "region": "us-east-1",
    "repository": "team/app",
    "tag": "1.0.0",
    "image": image,
    "platform": "linux/amd64",
    "verifyAfterWrite": "true",
    "timeoutSeconds": "20",
    "BUILD_NUMBER": "77",
}
data.update(json.loads(extra) if extra else {})
with open(f"{directory}/input.json", "w", encoding="utf-8") as handle:
    json.dump(data, handle)
