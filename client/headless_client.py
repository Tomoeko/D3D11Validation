#!/usr/bin/env python3
"""Signed, bounded maintenance over the existing pinned SSH transport.

The publisher key authorizes standard-account worker releases. It is independent
of SSH authentication and cannot update the privileged bootstrap or SSH settings.
"""
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


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def invoke(config, operation, envelope=None):
    if operation not in ('maintenance', 'maintenance-status'):
        raise ValueError('Unsupported maintenance operation')
    payload = b'' if envelope is None else encode(envelope)
    if len(payload) > 16384:
        raise ValueError('Maintenance request too large')
    process = subprocess.run(['ssh', '-F', str(config), 'd3d11-validation', operation],
                             input=payload, capture_output=True, timeout=25)
    if process.returncode:
        raise RuntimeError('Maintenance connection unavailable; bootstrap may not be installed')
    if len(process.stdout) > 16384:
        raise ValueError('Maintenance response too large')
    return json.loads(process.stdout)


def request(action, status, publication=None):
    active = status['active']
    if active['schema'] != 'd3d11-active-deployment/v1' or type(active['generation']) is not int:
        raise ValueError('Invalid active deployment')
    if not 1 <= active['generation'] < 999999999 or not re.fullmatch('[0-9a-f]{64}', active['policySha256']):
        raise ValueError('Invalid active identity')
    if action not in ('activate', 'repair', 'archive'):
        raise ValueError('Unsupported maintenance action')
    value = dict(version='1', requestId=secrets.token_hex(16), action=action,
                 generation=str(active['generation']), expectedPolicy=active['policySha256'],
                 deployment='-', policySha256='-', archiveSha256='-', archiveBytes='-', port='-',
                 ticket='-', certificateSha256='-', expiresUnix=str(int(time.time()) + 300))
    if action == 'activate':
        if publication is None:
            raise ValueError('Activation needs the reviewed package publication')
        for name in ('deployment', 'policySha256', 'archiveSha256', 'archiveBytes', 'port', 'ticket', 'certificateSha256'):
            value[name] = str(publication[name])
        if not re.fullmatch(r'worker-v[1-9][0-9]{0,8}', value['deployment']):
            raise ValueError('Invalid deployment name')
        for name in ('policySha256', 'archiveSha256', 'certificateSha256'):
            if not re.fullmatch('[0-9a-f]{64}', value[name]):
                raise ValueError('Invalid release digest')
        if not re.fullmatch('[0-9a-f]{48}', value['ticket']) or not 1 <= int(value['port']) <= 65535:
            raise ValueError('Invalid publication endpoint')
        if not 1 <= int(value['archiveBytes']) <= 268435456:
            raise ValueError('Invalid archive size')
    elif publication is not None:
        raise ValueError('Unexpected publication')
    return value


def sign(value, key):
    if key.stat().st_mode & 0o077:
        raise ValueError('Publisher private key must be readable only by its owner')
    data = encode(value)
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)],
                               input=data, capture_output=True, check=True).stdout
    if len(signature) != 384:
        raise ValueError('Use the approved RSA-3072 publisher key')
    return dict(request=base64.b64encode(data).decode('ascii'),
                signature=base64.b64encode(signature).decode('ascii'))


def verify_receipt(receipt, value):
    if receipt.get('schema') != 'd3d11-maintenance-receipt/v1' or receipt.get('requestId') != value['requestId']:
        raise ValueError('Maintenance receipt identity mismatch')
    if receipt.get('requestSha256') != hashlib.sha256(encode(value)).hexdigest():
        raise ValueError('Maintenance receipt binding mismatch')
    if receipt.get('phase') not in ('queued', 'prepared', 'staged', 'stopping', 'activated', 'completed', 'failed'):
        raise ValueError('Unknown maintenance phase')


def retrieve_receipt(config, envelope, value, deadline):
    # A lost response may follow successful activation. Retry only these same
    # signed bytes, with a fixed attempt bound; never create another operation.
    for attempt in range(3):
        try:
            receipt = invoke(config, 'maintenance', envelope)
            verify_receipt(receipt, value)
            return receipt
        except RuntimeError:
            if attempt == 2 or time.monotonic() + 2 >= deadline:
                raise
            time.sleep(2)
    raise AssertionError('Unreachable receipt retry')


def save_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'repair', 'archive', 'activate', 'retry'))
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--publisher-key', type=Path)
    parser.add_argument('--publication', type=Path, help='Private TLS publication metadata plus deployment and policySha256')
    parser.add_argument('--request-file', type=Path, help='Durable signed request, saved before sending; reuse with retry')
    parser.add_argument('--wait', type=int, default=180)
    args = parser.parse_args()
    if not 0 <= args.wait <= 600:
        parser.error('--wait must be between 0 and 600 seconds')
    if args.action == 'status':
        print(json.dumps(invoke(args.ssh_config, 'maintenance-status'), indent=2))
        return
    if not args.request_file:
        parser.error('A request file is required for crash-safe retries')
    if args.action == 'retry':
        envelope = json.loads(args.request_file.read_text())
        value = json.loads(base64.b64decode(envelope['request'], validate=True))
    else:
        if not args.publisher_key:
            parser.error('A publisher key is required')
        publication = json.loads(args.publication.read_text()) if args.publication else None
        value = request(args.action, invoke(args.ssh_config, 'maintenance-status'), publication)
        envelope = sign(value, args.publisher_key)
        save_new(args.request_file, envelope)
    deadline = time.monotonic() + args.wait
    receipt = retrieve_receipt(args.ssh_config, envelope, value, deadline)
    while receipt['phase'] not in ('completed', 'failed') and time.monotonic() < deadline:
        time.sleep(2)
        # Resending the exact signed request retrieves its durable receipt. The
        # server never creates a second maintenance execution for this identity.
        receipt = retrieve_receipt(args.ssh_config, envelope, value, deadline)
    print(json.dumps(receipt, indent=2))
    if receipt['phase'] == 'failed':
        raise SystemExit(1)
    if receipt['phase'] != 'completed':
        raise SystemExit('Pending; retain the request file and use retry')


if __name__ == '__main__':
    main()
