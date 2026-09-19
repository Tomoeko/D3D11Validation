#!/usr/bin/env python3
"""Package reviewed worker files; executable deployment is separate from job submission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKER_FILES = (
    'Validation.Runtime.cs', 'Validation.Protocol.psm1', 'Validation.Jobs.psm1',
    'Validation.Fixtures.psm1',
    'Get-ValidationSession.ps1', 'Invoke-ValidationJobGateway.ps1',
    'Start-ValidationWorker.ps1', 'Stop-ValidationWorker.ps1',
)


def gateway_entry(deployment):
    if not re.fullmatch(r'worker-v[1-9][0-9]*', deployment):
        raise ValueError('Invalid deployment name')
    # A nested PowerShell script's exit does not end the parent script. Preserve
    # its status explicitly so SSH callers can distinguish rejection from success.
    return ("& (Join-Path $PSScriptRoot '" + deployment +
            "/Invoke-ValidationJobGateway.ps1')\nexit $LASTEXITCODE\n").encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic', type=Path, required=True)
    parser.add_argument('--device-probe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--deployment', required=True, help='Protected directory name, such as worker-v5')
    parser.add_argument('--allow-dirty', action='store_true')
    args = parser.parse_args()
    state = subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True)
    if state and not args.allow_dirty:
        parser.error('Checkpoint the reviewed source or explicitly package a candidate with --allow-dirty')
    content = {name:(ROOT/'windows'/name).read_bytes() for name in WORKER_FILES}
    content['gateway-entry.ps1'] = gateway_entry(args.deployment)
    content['Test-JobRuntime.ps1'] = (ROOT/'tests/Test-JobRuntime.ps1').read_bytes()
    content['diagnostic.exe'] = args.diagnostic.read_bytes()
    content['native-baseline.json'] = (ROOT/'config/native-baseline.json').read_bytes()
    if args.device_probe:
        content['device-probe.exe'] = args.device_probe.read_bytes()
    hashes = {name:hashlib.sha256(data).hexdigest() for name,data in content.items()}
    policy = {
        'schema':'d3d11-worker-policy/v1',
        'sourceRevision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'sourceState':'candidate-not-checkpointed' if state else 'clean-checkpoint',
        'files':hashes,
    }
    content['worker-policy.json'] = (json.dumps(policy,indent=2)+'\n').encode()
    content['manifest.json'] = (json.dumps({name:hashlib.sha256(data).hexdigest()
                               for name,data in content.items()},indent=2)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(args.output,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,data in content.items(): archive.writestr(name,data)
    print(json.dumps({'archiveSha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      'fileCount':len(content),'sourceRevision':policy['sourceRevision'],
                      'sourceState':policy['sourceState']}))


if __name__ == '__main__': main()
