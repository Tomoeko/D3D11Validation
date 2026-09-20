#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Capture authenticated positive native observations for a shader consumer.

The binary output contains observations and identities, never certificate flags.
It is only produced after fresh retrieval of all twelve traced jobs. It does not
identify winning aliases, prove selection congruence, or assert image closure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

# Isolated Python excludes the script directory. Admit only this explicit
# adjacent client implementation; user-site and PYTHONPATH remain disabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unity_evidence import read_authority, require, retrieve_verified


KINDS = tuple(f'unity-{role}-{keyword}-tier{tier}-traced'
              for tier in range(3) for keyword in ('off', 'on')
              for role in ('recovered', 'regenerated'))
MAX_OUTPUT = 1024 * 1024


def sha(data):
    return hashlib.sha256(data).digest()


def decode_hash(value):
    require(isinstance(value, str) and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'Invalid digest')
    return bytes.fromhex(value)


def encode_capture(policy_hash, package_bytes, package, observations,
                   target_sha256, candidate_sha256):
    require(len(observations) == len(KINDS), 'Incomplete observation domain')
    members = package['files']
    require(isinstance(members, dict) and 1 <= len(members) <= 4096, 'Invalid package members')
    require(members['recovered.bundle'] == target_sha256 and
            members['regenerated.bundle'] == candidate_sha256, 'Bundle binding mismatch')
    first = observations[0][0]
    environment = first['result']['fixture']['environmentSha256']
    epoch = first['result']['workerEpoch']
    output = bytearray(b'DVUOBS01' + struct.pack('<III', 1, len(members), len(KINDS)))
    for value in (policy_hash, sha(package_bytes).hex(), environment, epoch,
                  target_sha256, candidate_sha256):
        output.extend(decode_hash(value))
    for name in sorted(members, key=lambda n: n.encode('utf-8')):
        encoded = name.encode('utf-8')
        require(0 < len(encoded) <= 4096 and '\x00' not in name and '\\' not in name and
                not name.startswith('/') and all(x not in ('', '.', '..') for x in name.split('/')),
                'Invalid member path')
        require(len(output) + len(encoded) + 36 <= MAX_OUTPUT, 'Observation output too large')
        output.extend(struct.pack('<I', len(encoded)))
        output.extend(encoded)
        output.extend(decode_hash(members[name]))
    seen = set()
    for kind, (response, files) in zip(KINDS, observations):
        record = response['result']
        require(record['kind'] == kind and record['workerEpoch'] == epoch and
                record['fixture']['environmentSha256'] == environment and
                response['deploymentSha256'] == policy_hash, 'Split observation authority')
        require(response['jobId'] not in seen, 'Duplicate job')
        seen.add(response['jobId'])
        output.extend(sha(json.dumps(response, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode('ascii')))
        # Retain complete bytes; consumers can use their existing DXBC parser
        # and exact comparator, rather than accepting a worker's PASS field.
        for name in ('draw-0001-vs.bin', 'draw-0001-ps.bin', 'pixels.bin', 'result.tsv'):
            data = files[name]
            require(0 < len(data) <= 65536, 'Invalid observation artifact size')
            require(len(output) + len(data) + 4 <= MAX_OUTPUT, 'Observation output too large')
            output.extend(struct.pack('<I', len(data)))
            output.extend(data)
        require(len(output) <= MAX_OUTPUT, 'Observation output too large')
    return bytes(output)


def collect(config, policy_path, jobs_path, target_sha256, candidate_sha256):
    decode_hash(target_sha256)
    decode_hash(candidate_sha256)
    policy_bytes = read_authority(policy_path)
    policy = json.loads(policy_bytes)
    package_path = policy_path.with_name('unity-package.json')
    package_bytes = read_authority(package_path)
    require(sha(package_bytes).hex() == policy['files']['unity-package.json'], 'Unpinned package')
    package = json.loads(package_bytes)
    require('selector-profile.bin' in package['files'], 'Selector observation unavailable')
    jobs_bytes = read_authority(jobs_path)
    jobs = json.loads(jobs_bytes)
    require(isinstance(jobs, list) and len(jobs) == len(KINDS), 'Incomplete job domain')
    by_kind = {}
    for job in jobs:
        require(isinstance(job, dict), 'Invalid job handle')
        kind = job.get('submitRequest', {}).get('kind')
        require(kind in KINDS and kind not in by_kind, 'Duplicate or unsupported job kind')
        by_kind[kind] = job
    observations = []
    for index, kind in enumerate(KINDS):
        expected = candidate_sha256 if index % 2 else target_sha256
        response, files, _ = retrieve_verified(config, by_kind[kind], policy_path, expected)
        observations.append((response, files))
    require(read_authority(policy_path) == policy_bytes and
            read_authority(package_path) == package_bytes and
            read_authority(jobs_path) == jobs_bytes, 'Capture authority changed')
    return encode_capture(sha(policy_bytes).hex(), package_bytes, package, observations,
                          target_sha256, candidate_sha256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--jobs', type=Path, required=True)
    parser.add_argument('--target-sha256', required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Output already exists')
        output = collect(args.ssh_config, args.policy, args.jobs, args.target_sha256,
                         args.candidate_sha256)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        # Job capabilities and raw authority records must not enter logs.
        print('Native observation capture failed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
