#!/usr/bin/env python3
"""Compile the fixed managed harness against the selected private player's assemblies."""
import argparse
import hashlib
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mono',type=Path,required=True)
    parser.add_argument('--compiler',type=Path,required=True)
    parser.add_argument('--managed-references',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Preserve existing compiled harnesses')
    source = Path(__file__).resolve().parents[1]/'unity/RenderRuntime.cs'
    references = sorted(p for p in args.managed_references.glob('*.dll') if p.name != 'Assembly-CSharp.dll')
    if not any(p.name == 'UnityEngine.CoreModule.dll' for p in references):
        parser.error('Selected private player core module is required')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    command = [str(args.mono),str(args.compiler),'/nologo','/noconfig','/nostdlib+',
               '/target:library','/optimize+','/deterministic','/out:' + str(args.output)]
    subprocess.run(command + ['/reference:' + str(p) for p in references] + [str(source)],check=True)
    print('Harness SHA-256:',hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == '__main__': main()
