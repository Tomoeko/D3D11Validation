#!/usr/bin/env python3
"""Typed SSH job client. Credentials and raw result records belong in ignored storage."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time

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


def submit(config, duration=0, nonce=None, kind="diagnostic"):
    request = {'version': '1', 'nonce': nonce or secrets.token_hex(32),
               'kind': kind, 'durationMs': str(duration)}
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
    fixture = (response.get('result') or {}).get('fixture')
    expected_kind = job.get('submitRequest', {}).get('kind')
    unity = isinstance(expected_kind, str) and expected_kind.startswith('unity-')
    if operation == 'results' and response.get('state') == 'completed' and (expected_kind == 'device' or unity) and not fixture:
        raise ValueError('Missing native preflight evidence')
    if fixture:
        expected_names = {'adapters.json','report.json','pixels.bin'}
        if unity:
            expected_names = {'unity-startup.json'}
            if expected_kind != 'unity-startup' and response['state'] == 'completed':
                expected_names = {'device.bin','draws.bin','result.tsv','pixels.bin'}
                if expected_kind.endswith('-traced'):
                    expected_names |= {f'draw-{draw:04d}-{stage}.bin' for draw in (1,2) for stage in ('vs','ps')}
        names = set()
        for artifact in fixture.get('artifacts', []):
            name = artifact.get('name')
            if name not in expected_names or name in names:
                raise ValueError('Unexpected artifact name')
            names.add(name)
            data = base64.b64decode(artifact['base64'], validate=True)
            if len(data) != artifact['byteLength'] or hashlib.sha256(data).hexdigest() != artifact['sha256']:
                raise ValueError('Artifact content mismatch')
        if response['state'] == 'completed' and names != expected_names:
            raise ValueError('Missing native preflight artifact')
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


def run_fixture(config, kind, policy_hash, output, timeout=90):
    """Run once, preserving the submit nonce, job identity and raw terminal result.

    Transport failure leaves durable recovery material. It never starts another
    job automatically or overwrites a previous investigation.
    """
    job_path = output.with_suffix('.job.json')
    if output.exists() or job_path.exists():
        raise FileExistsError('Preserve previous fixture evidence')
    nonce = secrets.token_hex(32)
    save(job_path, dict(schema='d3d11-pending-submit/v1', nonce=nonce,
                        kind=kind, durationMs=0))
    job = submit(config, kind=kind, nonce=nonce)
    save(job_path, job)
    if job['deploymentSha256'] != policy_hash:
        raise ValueError('Unapproved fixture deployment; job was not started')
    started = operate(config, 'start', job)
    job['executionNonce'] = started['executionNonce']
    save(job_path, job)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = operate(config, 'status', job)
        if status.get('recoveryRequired'):
            raise RuntimeError('Worker recovery required; preserve the interrupted job')
        if status['state'] in ('completed', 'failed', 'cancelled', 'timed_out', 'stale'):
            result = operate(config, 'results', job)
            save(output, result)
            return result
        time.sleep(1)
    raise TimeoutError('Fixture did not finish; preserve the job for status or cancellation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--job', type=Path)
    parser.add_argument('--duration-ms', type=int, default=0)
    parser.add_argument('--kind', default='diagnostic', help='Fixed fixture name approved by the server')
    parser.add_argument('operation', choices=sorted(OPERATIONS))
    args = parser.parse_args()
    if args.operation == 'status' and args.job is None:
        response = invoke(args.ssh_config, 'status')
    elif args.job is None:
        parser.error('--job is required for this operation')
    elif args.operation == 'submit':
        if args.job.exists():
            pending = json.loads(args.job.read_text())
            if pending.get('schema') != 'd3d11-pending-submit/v1':
                parser.error('Refusing to overwrite an existing local job')
            if pending['kind'] != args.kind or pending['durationMs'] != args.duration_ms:
                parser.error('Retry must use the original pending fixture and duration')
        else:
            pending = {'schema':'d3d11-pending-submit/v1', 'nonce':secrets.token_hex(32),
                       'kind':args.kind, 'durationMs':args.duration_ms}
            save(args.job, pending)
        response = submit(args.ssh_config, args.duration_ms, nonce=pending['nonce'], kind=args.kind)
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
