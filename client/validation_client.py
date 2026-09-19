#!/usr/bin/env python3
"""Typed SSH job client. Credentials and raw result records belong in ignored storage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

OPERATIONS = frozenset(('submit', 'start', 'status', 'results', 'cancel'))


def encode(request):
    return json.dumps(request, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def invoke(config, operation, request=None):
    if operation not in OPERATIONS:
        raise ValueError('Unsupported operation')
    payload = b'' if request is None else encode(request)
    if len(payload) > 8192:
        raise ValueError('Request too large')
    completed = subprocess.run(
        ['ssh', '-F', str(config), 'd3d11-validation', operation],
        input=payload, capture_output=True, timeout=25, check=False)
    if completed.returncode:
        # Remote errors contain categories only. Do not print credentials or request bodies.
        try:
            category = json.loads(completed.stderr).get('error', 'transport_failed')
        except (ValueError, AttributeError):
            category = 'transport_failed'
        raise RuntimeError(category)
    if len(completed.stdout) > 24 * 1024 * 1024:
        raise ValueError('Response too large')
    response = json.loads(completed.stdout)
    if request is not None and response.get('nonce') != request['nonce']:
        raise ValueError('Response nonce mismatch')
    return response


def submit(config, duration=0, nonce=None):
    request = {'version': '1', 'nonce': nonce or secrets.token_hex(32),
               'kind': 'diagnostic', 'durationMs': str(duration)}
    response = invoke(config, 'submit', request)
    if response.get('inputSha256') != hashlib.sha256(encode(request)).hexdigest():
        raise ValueError('Input binding mismatch')
    for key, length in (('jobId', 32), ('capability', 64), ('deploymentSha256', 64)):
        if not re.fullmatch('[0-9a-f]{' + str(length) + '}', response.get(key, '')):
            raise ValueError('Invalid server job identity')
    response['submitRequest'] = request
    return response


def operate(config, operation, job):
    request = {'version': '1', 'nonce': secrets.token_hex(32),
               'jobId': job['jobId'], 'capability': job['capability']}
    response = invoke(config, operation, request)
    for key in ('jobId', 'inputSha256', 'deploymentSha256'):
        if response.get(key) != job[key]:
            raise ValueError('Job binding mismatch: ' + key)
    expected_execution = job.get('executionNonce', '')
    if expected_execution and response.get('executionNonce') != expected_execution:
        raise ValueError('Execution binding mismatch')
    if operation == 'results' and response.get('state') == 'completed':
        result = response.get('result')
        if not isinstance(result, dict) or result.get('completion') != 'completed':
            raise ValueError('Incomplete result')
        for key in ('jobId', 'inputSha256', 'deploymentSha256', 'executionNonce'):
            if result.get(key) != response[key]:
                raise ValueError('Result binding mismatch: ' + key)
        if not response['executionNonce'] or response.get('exitCode') != 0:
            raise ValueError('Missing successful execution')
    return response


def save(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--job', type=Path)
    parser.add_argument('--duration-ms', type=int, default=0)
    parser.add_argument('operation', choices=sorted(OPERATIONS))
    args = parser.parse_args()
    if args.operation == 'status' and args.job is None:
        response = invoke(args.ssh_config, 'status')
    elif args.job is None:
        parser.error('--job is required for this operation')
    elif args.operation == 'submit':
        if args.job.exists():
            parser.error('Refusing to overwrite an existing local job')
        response = submit(args.ssh_config, args.duration_ms)
        save(args.job, response)
    else:
        job = json.loads(args.job.read_text())
        response = operate(args.ssh_config, args.operation, job)
        if args.operation == 'start':
            job['executionNonce'] = response['executionNonce']
            save(args.job, job)
        if args.operation == 'results':
            save(args.job.with_suffix('.result.json'), response)
    print(json.dumps({key: value for key, value in response.items()
                      if key not in ('capability', 'submitRequest', 'result')}, indent=2))


if __name__ == '__main__':
    main()
