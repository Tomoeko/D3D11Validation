#!/usr/bin/env python3
"""Compare the fixed Unity corpus on one pinned native Windows environment.

Acceptance is bitwise between native recovered/regenerated pairs and repeats.
The package's historical pixel hash is reported separately, never used to excuse
or conceal a native pair mismatch. Capture-off still retains draw observation;
it does not qualify completely uninstrumented execution.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from adapter_evidence import verify_selection

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('client', ROOT/'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(result, kind, policy_hash, policy, package, baseline):
    require(result['deploymentSha256'] == policy_hash, 'Deployment mismatch')
    require(result['state'] == 'completed' and result['exitCode'] == 0, 'Unity execution failed')
    record = result['result']
    require(record['kind'] == kind and record['failureCode'] is None, 'Fixture mismatch')
    require(record['sourceRevision'] == policy['sourceRevision'] and
            record['sourceState'] == policy['sourceState'], 'Source provenance mismatch')
    require(record['binarySha256'] == package['files']['RuntimeProbe.exe'], 'Private player mismatch')
    fixture = record['fixture']
    files = {a['name']:base64.b64decode(a['base64'],validate=True) for a in fixture['artifacts']}
    env = fixture['environment']
    verify_selection(record, files, baseline, policy)
    for key, expected in [('featureLevel',package['featureLevel']), ('creationFlags',package['creationFlags']),
                          ('operatingSystem',baseline['operatingSystem']), ('processSessionId',0),
                          ('clientProtocolType',-1), ('connectionState',-1), ('executionContext','Session0')]:
        require(env[key] == expected, 'Environment mismatch: ' + key)
    require(len(env['runtimeIdentities']) == len(baseline['runtimeIdentities']), 'Runtime count mismatch')
    for actual, expected in zip(env['runtimeIdentities'],baseline['runtimeIdentities']):
        for key in ('file','version','sha256'):
            require(actual[key] == expected[key], 'Native runtime drift')
        signature = dict(type=actual['signatureType'], signer=actual['signer'],
                         certificateSha256=actual['certificateSha256'])
        require(actual['signatureStatus'] == 'Valid' and signature in expected['signatures'], 'Signer drift')
    require(digest(json.dumps(env,separators=(',',':'),ensure_ascii=False).encode()) ==
            fixture['environmentSha256'], 'Environment content mismatch')
    require(env['nativeHardwarePreflightPassed'] and not env['fullQualificationComplete'], 'Qualification mismatch')
    expected_images = ['RuntimeProbe.exe', 'UnityPlayer.dll',
                       'MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll',
                       'RuntimeProbe_Data/Managed/Assembly-CSharp.dll']
    require(env.get('playerImages') == [dict(file=name, sha256=package['files'][name])
                                       for name in expected_images], 'Loaded player image drift')
    require(env.get('loadedImageClosureComplete') is False, 'Unexpected complete image closure claim')
    comparison = fixture['comparison']
    require(comparison['case'] == kind and comparison['profileMatched'] and
            comparison['repeatedPixelsEqual'], 'Profile or repeat mismatch')
    traced = kind.endswith('-traced')
    require(comparison['captureEnabled'] == traced and comparison['drawHooksEnabled'] ==
            (not kind.endswith('-unhooked')), 'Instrumentation mode mismatch')
    require(len(files['pixels.bin']) == 256, 'Incomplete pixels')
    if traced:
        for stage in ('vs','ps'):
            first = files[f'draw-0001-{stage}.bin']
            require(first == files[f'draw-0002-{stage}.bin'], 'Repeated bound shader mismatch')
            require(first[:4] == b'DXBC' and len(first) >= 32 and
                    struct.unpack_from('<I',first,24)[0] == len(first), 'Incomplete DXBC')
            if 'negative' not in kind or stage == 'vs':
                require(digest(first) == package['referenceDxbc'][stage], 'Unexpected bound shader')
    return files, fixture['environmentSha256']


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
