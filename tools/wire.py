#!/usr/bin/env python3
"""Filter the fake ECR's request log: print the records that contain a needle.

usage: wire.py <log> <needle>
"""
import json
import sys

needle = sys.argv[2]
for line in open(sys.argv[1], encoding="utf-8"):
    record = json.loads(line)
    if needle in json.dumps(record, ensure_ascii=False):
        print(json.dumps(record, ensure_ascii=False))
