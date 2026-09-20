#!/usr/bin/env python3
"""Package a private Unity player and fixed fixtures with explicit instrumentation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

EXCLUDED = {'d3d11.dll', 'dxgi.dll', 'dxbc_d3d11_original.dll', 'validation-observer.dll'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--player', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--trace-library', type=Path)
    parser.add_argument('--observer-library', type=Path)
    parser.add_argument('--managed-harness', type=Path)
    parser.add_argument('--regenerated-bundle', type=Path)
    parser.add_argument('--negative-bundle', type=Path)
    parser.add_argument('--creation-flags', type=int)
    parser.add_argument('--feature-level', type=int)
    parser.add_argument('--reference-vs', type=Path)
    parser.add_argument('--reference-ps', type=Path)
    parser.add_argument('--reference-pixels', type=Path)
    parser.add_argument('--deployment', required=True)
    parser.add_argument('--adapter-ordinal', type=int, choices=range(64), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.trace_library and args.observer_library:
        parser.error('Capture and unhooked observation require separate package directories')
    mode = 'unhooked' if args.observer_library else ('draw' if args.trace_library else 'startup')
    if not re.fullmatch(r'unity-' + mode + r'-v[1-9][0-9]*', args.deployment):
        parser.error('Invalid deployment name')
    if mode != 'startup' and not all((args.regenerated_bundle, args.negative_bundle, args.reference_vs,
                                   args.reference_ps, args.reference_pixels)):
        parser.error('Draw packages require both other bundles and complete reference artifacts')
    if mode != 'startup' and (args.creation_flags is None or args.feature_level is None or not args.managed_harness):
        parser.error('Draw packages require a reviewed managed harness, native feature level and creation flags')
    if args.output.exists() or args.manifest.exists():
        parser.error('Preserve existing packages and manifests')
    content = {}
    for path in sorted(args.player.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinks are not accepted in player packages')
        if path.is_dir():
            continue
        if path.name.lower() in EXCLUDED:
            continue
        name = path.relative_to(args.player).as_posix()
        if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_. /-]*', name):
            raise ValueError('Unsupported player filename')
        content[name] = path.read_bytes()
    if mode == 'startup':
        content['fixture.bundle'] = args.bundle.read_bytes()
    else:
        content['recovered.bundle'] = args.bundle.read_bytes()
        content['regenerated.bundle'] = args.regenerated_bundle.read_bytes()
        content['negative.bundle'] = args.negative_bundle.read_bytes()
        content['RuntimeProbe_Data/Managed/Assembly-CSharp.dll'] = args.managed_harness.read_bytes()
        if mode == 'draw': content['d3d11.dll'] = args.trace_library.read_bytes()
        else: content['validation-observer.dll'] = args.observer_library.read_bytes()
    required = {'RuntimeProbe.exe', 'UnityPlayer.dll', 'RuntimeProbe_Data/globalgamemanagers'}
    if not required <= content.keys():
        raise ValueError('Missing required private player files')
    manifest = dict(schema='d3d11-unity-' + mode + '-package/v1', deployment=args.deployment,
                    adapterOrdinal=args.adapter_ordinal,
                    files={name: hashlib.sha256(data).hexdigest() for name, data in content.items()})
    if mode != 'startup':
        manifest['creationFlags'] = args.creation_flags
        manifest['featureLevel'] = args.feature_level
        manifest['referenceDxbc'] = {stage: hashlib.sha256(path.read_bytes()).hexdigest()
                                     for stage, path in [('vs', args.reference_vs), ('ps', args.reference_ps)]}
        manifest['referencePixels'] = hashlib.sha256(args.reference_pixels.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, data in content.items():
            archive.writestr(name, data)
    args.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(fileCount=len(content),
                         archiveSha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
                         manifestSha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
