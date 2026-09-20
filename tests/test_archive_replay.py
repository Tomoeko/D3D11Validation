#!/usr/bin/env python3
"""Verify archived submissions cannot become new executions after queue rotation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def rejected(action, category):
    try:
        action()
    except RuntimeError as error:
        if str(error) != category:
            raise
    else:
        raise AssertionError('Archived request was accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--archived-job', type=Path, action='append', required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Preserve existing evidence')
    for path in args.archived_job:
        job = json.loads(path.read_text())
        request = job['submitRequest']
        rejected(lambda: client.invoke(args.ssh_config, 'submit', request), 'request_archived')
        changed = dict(request, kind='diagnostic', durationMs=('0' if request['durationMs'] == '1' else '1'))
        rejected(lambda: client.invoke(args.ssh_config, 'submit', changed), 'nonce_conflict')
        rejected(lambda: client.operate(args.ssh_config, 'start', job), 'job_unavailable')
    policy = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    result = client.run_fixture(args.ssh_config, 'diagnostic', policy, args.output.with_suffix('.diagnostic.json'))
    if result['state'] != 'completed' or result['exitCode'] != 0:
        raise AssertionError('Fresh diagnostic failed')
    client.save(args.output, dict(schema='d3d11-archive-replay/v1',
        deploymentSha256=policy, archivedJobsChecked=len(args.archived_job),
        replayRejected=True, nonceConflictRejected=True, oldStartRejected=True,
        freshDiagnosticPassed=True))
    print('PASS: archived replay/conflict/start rejected; fresh diagnostic completed')


if __name__ == '__main__':
    main()
