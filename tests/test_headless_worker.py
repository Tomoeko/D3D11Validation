#!/usr/bin/env python3
"""Physical-host acceptance for signed headless repair and request boundaries.

Requires the reviewed bootstrap already installed. No reboot, removal, account,
firewall or SSH configuration changes are made by this test.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


maintenance = load('maintenance', 'client/headless_client.py')
client = load('jobs', 'client/validation_client.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--publisher-key', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(exist_ok=False)
    policy_sha = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    before = maintenance.invoke(args.ssh_config, 'maintenance-status')
    assert before['active']['policySha256'] == policy_sha
    worker_before = client.invoke(args.ssh_config, 'status')['worker']
    assert worker_before['sessionId'] == 0 and worker_before['elevated'] is False
    assert not worker_before['activeJob'], 'Preserve an active job before maintenance acceptance'
    checks = 0

    def reject(envelope):
        nonlocal checks
        try:
            maintenance.invoke(args.ssh_config, 'maintenance', envelope)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Invalid maintenance request accepted')
        after = maintenance.invoke(args.ssh_config, 'maintenance-status')
        assert after['active'] == before['active'] and not after['requestPending']
        checks += 1

    value = maintenance.request('repair', before)
    valid = maintenance.sign(value, args.publisher_key)
    bad = dict(valid)
    signature = bytearray(base64.b64decode(bad['signature']))
    signature[0] ^= 1
    bad['signature'] = base64.b64encode(signature).decode()
    reject(bad)
    bad = dict(value, generation=str(int(value['generation']) + 1))
    reject(maintenance.sign(bad, args.publisher_key))
    bad = dict(value, expiresUnix=str(int(time.time()) - 1))
    reject(maintenance.sign(bad, args.publisher_key))
    bad = dict(value, action='shell')
    reject(maintenance.sign(bad, args.publisher_key))

    request_file = args.output_directory / 'repair-request.json'
    subprocess.run([sys.executable, str(ROOT / 'client/headless_client.py'), 'repair',
                    '--ssh-config', str(args.ssh_config), '--publisher-key', str(args.publisher_key),
                    '--request-file', str(request_file)], check=True)
    envelope = json.loads(request_file.read_text())
    value = json.loads(base64.b64decode(envelope['request']))
    receipt = maintenance.invoke(args.ssh_config, 'maintenance', envelope)
    maintenance.verify_receipt(receipt, value)
    assert receipt['phase'] == 'completed'
    checks += 1
    after = maintenance.invoke(args.ssh_config, 'maintenance-status')
    assert after['active']['generation'] == before['active']['generation'] + 1
    assert after['active']['policySha256'] == policy_sha
    assert not after['requestPending']
    assert maintenance.invoke(args.ssh_config, 'maintenance', envelope) == receipt
    assert maintenance.invoke(args.ssh_config, 'maintenance-status')['active'] == after['active']
    checks += 1
    deadline = time.monotonic() + 30
    while True:
        try:
            worker_after = client.invoke(args.ssh_config, 'status')['worker']
            if worker_after['epoch'] != worker_before['epoch']:
                break
        except RuntimeError:
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError('Repaired worker did not become ready')
        time.sleep(1)
    assert worker_after['sessionId'] == 0 and worker_after['elevated'] is False
    assert worker_after['dedicatedAccount'] and worker_after['deploymentSha256'] == policy_sha
    checks += 1
    result = client.run_fixture(args.ssh_config, 'diagnostic', policy_sha, args.output_directory / 'diagnostic.json')
    assert result['state'] == 'completed' and result['exitCode'] == 0
    checks += 1
    client.save(args.output_directory / 'acceptance.json', dict(schema='d3d11-headless-maintenance-acceptance/v1',
        checksPassed=checks, standardSession0Worker=True, repairReplacedWorkerEpoch=True,
        exactRetryDidNotRerun=True, invalidRequestsDidNotMutate=True, diagnosticPassed=True,
        deploymentSha256=policy_sha, rebootQualified=False, activationQualified=False, cleanInstallQualified=False))
    print('PASS: signed repair, replay and rejection boundaries, standard Session 0 worker, diagnostic')


if __name__ == '__main__':
    main()
