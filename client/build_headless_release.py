#!/usr/bin/env python3
"""Wrap a verified worker archive for signed installation into a new release slot."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


def build(worker_archive, deployment, output, unity_archive=None, unhooked_archive=None):
    if not re.fullmatch(r'worker-v[1-9][0-9]{0,8}', deployment):
        raise ValueError('Invalid deployment')
    content = {}
    with zipfile.ZipFile(worker_archive) as source:
        if not 1 <= len(source.infolist()) <= 128:
            raise ValueError('Invalid worker archive count')
        total = 0
        folded = set()
        for item in source.infolist():
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', item.filename) or item.filename.endswith('.'):
                raise ValueError('Invalid worker filename')
            if item.filename.lower() in folded or (item.external_attr >> 16) & 0xf000 not in (0, 0x8000):
                raise ValueError('Duplicate or non-regular worker member')
            folded.add(item.filename.lower())
            total += item.file_size
            if item.file_size > 134217728 or total > 268435456:
                raise ValueError('Worker archive too large')
            content[item.filename] = source.read(item)
    manifest = json.loads(content['manifest.json'])
    if set(content) != set(manifest) | {'manifest.json'}:
        raise ValueError('Worker manifest does not cover the archive')
    for name, expected in manifest.items():
        if hashlib.sha256(content[name]).hexdigest() != expected:
            raise ValueError('Worker manifest content mismatch')
    policy = json.loads(content['worker-policy.json'])
    if policy['schema'] != 'd3d11-worker-policy/v1' or policy['executionContext'] != 'Session0':
        raise ValueError('Only an approved Session 0 worker can be installed')
    if set(content) != set(policy['files']) | {'manifest.json', 'worker-policy.json'}:
        raise ValueError('Worker policy does not cover the archive')
    for name, expected in policy['files'].items():
        if hashlib.sha256(content[name]).hexdigest() != expected:
            raise ValueError('Worker policy content mismatch')
    release = {deployment + '/' + name: data for name, data in content.items()}
    for filename, package_archive, mode in [('unity-package.json', unity_archive, 'draw'),
                                            ('unhooked-package.json', unhooked_archive, 'unhooked')]:
        if package_archive is None:
            continue
        package = json.loads(content[filename])
        root = package['deployment']
        if (not re.fullmatch(r'unity-' + mode + r'-v[1-9][0-9]{0,8}', root) or
                package['schema'] != 'd3d11-unity-' + mode + '-package/v2' or
                package['adapterSelection'] != 'unique-current-inventory'):
            raise ValueError('Invalid Unity package contract')
        members = {}
        with zipfile.ZipFile(package_archive) as source:
            if not 4 <= len(source.infolist()) <= 1024:
                raise ValueError('Invalid Unity archive count')
            folded = set()
            total = 0
            for item in source.infolist():
                name = item.filename
                parts = name.split('/')
                if (not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_. /-]*', name) or
                        len(parts) > 15 or len(root + '/' + name) > 220 or
                        any(p in ('', '.', '..') or p.endswith(('.', ' ')) or
                            re.fullmatch(r'(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', p, re.I) for p in parts) or
                        name.lower() in folded or (item.external_attr >> 16) & 0xf000 not in (0, 0x8000)):
                    raise ValueError('Invalid Unity archive member')
                folded.add(name.lower())
                total += item.file_size
                if item.file_size > 134217728 or total > 268435456:
                    raise ValueError('Unity archive too large')
                members[name] = source.read(item)
        if set(members) != set(package['files']):
            raise ValueError('Unity manifest does not cover the archive')
        for name, data in members.items():
            if hashlib.sha256(data).hexdigest() != package['files'][name]:
                raise ValueError('Unity manifest content mismatch')
            if any('/'.join(name.lower().split('/')[:i]) in folded for i in range(1, len(name.split('/')))):
                raise ValueError('Unity file-directory conflict')
            release[root + '/' + name] = data
    if len(release) > 4096 or sum(map(len, release.values())) > 536870912:
        raise ValueError('Release too large')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as destination:
        for name, data in release.items():
            destination.writestr(name, data)
    if output.stat().st_size > 268435456:
        raise ValueError('Compressed release too large')
    return dict(deployment=deployment, policySha256=hashlib.sha256(content['worker-policy.json']).hexdigest(),
                archiveSha256=hashlib.sha256(output.read_bytes()).hexdigest(), archiveBytes=output.stat().st_size,
                files=len(release), schema='d3d11-headless-release/v1')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-archive', type=Path, required=True)
    parser.add_argument('--deployment', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--unity-archive', type=Path)
    parser.add_argument('--unhooked-archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.worker_archive, args.deployment, args.output, args.unity_archive, args.unhooked_archive), indent=2))


if __name__ == '__main__':
    main()
