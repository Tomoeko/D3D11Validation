#!/usr/bin/env python3
"""Retrieve a bounded Unity startup observation; never claim GPU qualification."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix('.job.json').exists():
        parser.error('Preserve previous investigations')
    expected = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    result = client.run_fixture(args.ssh_config, 'unity-startup', expected, args.output)
    print(json.dumps({key: result[key] for key in ('state', 'exitCode')}))
    record = result.get('result') or {}
    print(json.dumps(dict(failureCode=record.get('failureCode'))))
    for artifact in (record.get('fixture') or {}).get('artifacts', []):
        summary = json.loads(base64.b64decode(artifact['base64'], validate=True))
        assert not summary['fullQualificationComplete'] and not summary['loadedRuntimeQualified']
        print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
