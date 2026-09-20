#!/usr/bin/env python3
"""Build the one-time, locally reviewed headless bootstrap for an existing host."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'Manage-ValidationHeadless.ps1', 'Invoke-ValidationHeadless.ps1',
    'Start-ValidationHeadlessWorker.ps1', 'Invoke-ValidationMaintenance.ps1',
    'Validation.Headless.psm1', 'Validation.Maintenance.psm1', 'Validation.Maintenance.cs',
    'Validation.Setup.psm1', 'Validation.Task.psm1', 'Archive-ValidationQueue.ps1',
    'Validation.Archive.psm1', 'Validation.Submission.psm1', 'Validation.Protocol.psm1',
    'Validation.Runtime.cs',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build(output, publisher, deployment, policy_sha, gateway_sha, ssh_sha, client_address):
    if not re.fullmatch(r'worker-v[1-9][0-9]{0,8}', deployment):
        raise ValueError('Invalid deployment')
    for value in (policy_sha, gateway_sha, ssh_sha):
        if not re.fullmatch('[0-9a-f]{64}', value):
            raise ValueError('Invalid deployment pin')
    address = ipaddress.ip_address(client_address)
    if address.version != 4 or not address.is_link_local or str(address) != client_address:
        raise ValueError('Use the reviewed link-local client address')
    content = {name: (ROOT / 'windows' / name).read_bytes() for name in FILES}
    public_key = publisher.read_bytes()
    if b'<D>' in public_key or not public_key.startswith(b'<RSAKeyValue>'):
        raise ValueError('Only the public publisher XML belongs in the bootstrap')
    content['publisher.xml'] = public_key
    manifest = (json.dumps({name: digest(data) for name, data in content.items()}, indent=2) + '\n').encode()
    content['source-manifest.json'] = manifest
    source_sha = digest(manifest)
    # All interpolations are validated fixed-format strings, never shell input.
    content['Install-Headless.ps1'] = (
        "$ErrorActionPreference = 'Stop'\n"
        "& (Join-Path $PSScriptRoot 'Manage-ValidationHeadless.ps1') -Mode Install -ResumeRolledBack `\n"
        f"    -Deployment '{deployment}' -PolicySha256 '{policy_sha}' `\n"
        f"    -SourceManifestSha256 '{source_sha}' `\n"
        f"    -GatewaySha256 '{gateway_sha}' `\n"
        f"    -SshConfigurationSha256 '{ssh_sha}' `\n"
        "    -PublisherKeyPath (Join-Path $PSScriptRoot 'publisher.xml') `\n"
        f"    -ClientAddress '{client_address}'\n"
    ).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, data in content.items():
            archive.writestr(name, data)
    return dict(schema='d3d11-headless-bootstrap/v1', archiveSha256=digest(output.read_bytes()),
                sourceManifestSha256=source_sha, publisherSha256=digest(public_key),
                files=len(content), privateKeyIncluded=False, existingHostOnly=True,
                windowsAcceptance='not-run', rebootAcceptance='not-run')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--publisher', required=True, type=Path)
    parser.add_argument('--deployment', required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--gateway-sha256', required=True)
    parser.add_argument('--ssh-sha256', required=True)
    parser.add_argument('--client-address', required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.publisher, args.deployment, args.policy_sha256,
                           args.gateway_sha256, args.ssh_sha256, args.client_address), indent=2))


if __name__ == '__main__':
    main()
