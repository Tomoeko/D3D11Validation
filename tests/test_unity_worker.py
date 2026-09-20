#!/usr/bin/env python3
"""Compare the fixed Unity corpus on one pinned native Windows environment.

Acceptance is bitwise between native recovered/regenerated pairs and repeats.
The package's historical pixel hash is reported separately, never used to excuse
or conceal a native pair mismatch. Capture-off still retains draw observation;
it does not qualify completely uninstrumented execution.
"""
import argparse
import json
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
from unity_evidence import digest, require, verify
import validation_client as client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config',type=Path,default=Path('.local/ssh_config'))
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Preserve previous campaign evidence')
    policy = json.loads(args.policy.read_text()); policy_hash = digest(args.policy.read_bytes())
    package_bytes = args.policy.with_name('unity-package.json').read_bytes()
    require(digest(package_bytes) == policy['files']['unity-package.json'], 'Unpinned Unity package')
    package = json.loads(package_bytes)
    unhooked_bytes = args.policy.with_name('unhooked-package.json').read_bytes()
    require(digest(unhooked_bytes) == policy['files']['unhooked-package.json'], 'Unpinned unhooked package')
    unhooked = json.loads(unhooked_bytes)
    for name in ('RuntimeProbe.exe','UnityPlayer.dll','RuntimeProbe_Data/globalgamemanagers',
                 'RuntimeProbe_Data/Managed/Assembly-CSharp.dll','recovered.bundle','regenerated.bundle','negative.bundle'):
        require(package['files'][name] == unhooked['files'][name], 'Packages differ beyond instrumentation')
    baseline = json.loads(args.policy.with_name('native-baseline.json').read_text())
    campaign = dict(schema='d3d11-unity-worker-campaign/v1', deploymentSha256=policy_hash,
                    comparisonRule='bitwise-native-pairs-and-repeats', captureOffRetainsObservation=True,
                    campaignAccepted=False, fullQualificationComplete=False, results=[])
    files_by_case = {}; environment = None

    def run(kind):
        nonlocal environment
        output = args.output.with_suffix('.case-' + str(len(campaign['results'])) + '.json')
        result = client.run_fixture(args.ssh_config,kind,policy_hash,output)
        campaign['results'].append(result); client.save(args.output,campaign)
        selected = unhooked if kind.endswith('-unhooked') else package
        files, env = verify(result,kind,policy_hash,policy,selected,baseline)
        if environment is None: environment = env
        require(environment == env, 'Environment changed within campaign')
        print('PASS execution:',kind,flush=True)
        return files

    for keyword in ('off','on'):
        for tier in range(3):
            pair = {}
            for bundle in ('recovered','regenerated'):
                for capture in ('traced','untraced','unhooked'):
                    kind = f'unity-{bundle}-{keyword}-tier{tier}-{capture}'
                    pair[bundle,capture] = run(kind)
                    files_by_case[kind] = pair[bundle,capture]
            original = pair['recovered','traced']
            for files in pair.values():
                require(original['pixels.bin'] == files['pixels.bin'], 'Native pixels differ between pair or capture mode')
            for stage in ('vs','ps'):
                name = f'draw-0001-{stage}.bin'
                require(original[name] == pair['regenerated','traced'][name], 'Native DXBC differs between pair')
            print(f'PASS bitwise pair across all instrumentation modes: {keyword} tier {tier}',flush=True)
    for bundle in ('recovered','regenerated'):
        kind = f'unity-{bundle}-off-tier0-traced'
        repeated = run(kind)
        for name in ('pixels.bin','draw-0001-vs.bin','draw-0001-ps.bin'):
            require(repeated[name] == files_by_case[kind][name], 'Independent launch differs')
    original = files_by_case['unity-recovered-off-tier0-traced']
    for capture in ('traced','untraced','unhooked'):
        negative = run('unity-negative-off-tier0-' + capture)
        require(negative['pixels.bin'] != original['pixels.bin'], 'Wrong-sign pixel control was not detected')
        if capture == 'traced':
            require(negative['draw-0001-ps.bin'] != original['draw-0001-ps.bin'], 'Wrong-sign DXBC control was not detected')
    campaign['unhookedComparisonPassed'] = True
    campaign['campaignAccepted'] = True
    client.save(args.output,campaign)
    print('PASS: 12 native cases in three instrumentation modes, independent repeat launches, and wrong-sign controls')


if __name__ == '__main__': main()
