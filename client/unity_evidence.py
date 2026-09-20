# SPDX-License-Identifier: GPL-3.0-only
"""Verify authenticated native Unity observations against a pinned deployment.

The pure verification helpers validate record contents only. Use retrieve_verified
for fresh authenticated retrieval; neither API certifies runtime selection or
whole-shader equivalence.
"""
import base64
import hashlib
import json
import re
import struct

from adapter_evidence import verify_selection
import validation_client


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_authority(path):
    with path.open('rb') as stream:
        data = stream.read(1024 * 1024 + 1)
    require(len(data) <= 1024 * 1024, 'Authority file too large')
    return data


def verify_player_record(data, kind, package, pixels):
    """Bind raw player observations independently of the worker comparison flags."""
    require(len(data) <= 65536, 'Player record too large')
    match = re.fullmatch(r'unity-(recovered|regenerated|negative)-(off|on)-tier([0-2])-(traced|untraced|unhooked)', kind)
    require(match is not None, 'Unsupported draw fixture')
    bundle, keyword, tier, mode = match.groups()
    fields = {}
    declarations = []
    for line in data.decode('utf-8', errors='strict').splitlines():
        require(line.count('\t') == 1, 'Invalid player record line')
        key, value = line.split('\t')
        require(key and value and '\x00' not in line, 'Invalid player record field')
        if key == 'keyword_decl':
            require(value not in declarations, 'Duplicate keyword declaration')
            declarations.append(value)
        else:
            require(key not in fields, 'Duplicate player record field')
            fields[key] = value
    expected = {
        'schema': 'dxbc-private-player-draw-domain/v3',
        'instrumentation': {'traced': 'on', 'untraced': 'off', 'unhooked': 'none'}[mode],
        'bundle_sha256': package['files'][bundle + '.bundle'],
        'player_metadata_sha256': package['files']['RuntimeProbe_Data/globalgamemanagers'],
        'harness_sha256': package['files']['RuntimeProbe_Data/Managed/Assembly-CSharp.dll'],
        'unity_version': '2021.3.35f1', 'backend': 'Direct3D11',
        'render_threading': 'Direct', 'fog_enabled': 'False', 'fog_mode': 'Linear',
        'fog_input_float32le': '0000803e0000003f0000403f0000803f00000000000096430ad7233c',
        'active_tier_enum': tier, 'color_space': 'Gamma',
        'supported': 'True', 'pass_count': '1',
        'uv_variant_enabled': 'True' if keyword == 'on' else 'False',
        'material_keyword_count': '0', 'mesh': 'canonical-quad-position-identity-v1',
        'render_target': '4x4-rgba32f-linear-depth24-msaa1',
        'pixel_bytes': str(len(pixels)), 'pixels_sha256': digest(pixels),
        'repeated_pixels_equal': 'True', 'set_pass': 'True',
    }
    for key, value in expected.items():
        require(fields.get(key) == value, 'Raw player observation mismatch: ' + key)
    require(set(fields) == set(expected) | {'harness_path', 'device', 'driver', 'asset', 'shader', 'pass_name'},
            'Unexpected player record shape')
    require(declarations == ['STEREO_INSTANCING_ON:True', 'UNITY_SINGLE_PASS_STEREO:True',
                            'STEREO_MULTIVIEW_ON:True', 'STEREO_CUBEMAP_RENDER_ON:True',
                            'UV_VARIANT:True'], 'Keyword declaration drift')
    return fields


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
    observed = verify_player_record(files['result.tsv'], kind, package, files['pixels.bin'])
    require(observed['device'] == env['adapter']['name'], 'Raw device observation drift')
    if traced:
        for stage in ('vs','ps'):
            first = files[f'draw-0001-{stage}.bin']
            require(first == files[f'draw-0002-{stage}.bin'], 'Repeated bound shader mismatch')
            require(first[:4] == b'DXBC' and len(first) >= 32 and
                    struct.unpack_from('<I',first,24)[0] == len(first), 'Incomplete DXBC')
            if 'negative' not in kind or stage == 'vs':
                require(digest(first) == package['referenceDxbc'][stage], 'Unexpected bound shader')
    return files, fixture['environmentSha256']


def retrieve_verified(config, job, policy_path, expected_bundle_sha256):
    """Retrieve an existing job over SSH and reject worker/policy/input drift.

    No caller-supplied result is accepted. The expected bundle digest must come
    from the consumer's own captured artifact, not a result report. The returned
    observations still have finite scope and incomplete loaded-image closure.
    This operation never submits, restarts or silently reruns a job.
    """
    require(isinstance(expected_bundle_sha256, str) and
            re.fullmatch('[0-9a-f]{64}', expected_bundle_sha256), 'Invalid expected bundle digest')
    kind = job.get('submitRequest', {}).get('kind', '')
    match = re.fullmatch(r'unity-(recovered|regenerated|negative)-(off|on)-tier([0-2])-(traced|untraced|unhooked)', kind)
    require(match is not None, 'Unsupported draw fixture')
    policy_bytes = read_authority(policy_path)
    policy = json.loads(policy_bytes)
    policy_hash = digest(policy_bytes)
    require(policy.get('schema') == 'd3d11-worker-policy/v1' and
            policy.get('executionContext') == 'Session0', 'Unsupported worker policy')
    require(job.get('deploymentSha256') == policy_hash, 'Job policy mismatch')
    snapshots = [(policy_path, policy_bytes)]

    def load_member(name):
        path = policy_path.with_name(name)
        data = read_authority(path)
        require(digest(data) == policy['files'][name], 'Unpinned authority: ' + name)
        snapshots.append((path, data))
        return json.loads(data)

    package = load_member('unhooked-package.json' if kind.endswith('-unhooked') else 'unity-package.json')
    baseline = load_member('native-baseline.json')
    require(package['files'][match[1] + '.bundle'] == expected_bundle_sha256, 'Captured bundle differs from approved input')

    def worker():
        status = validation_client.invoke(config, 'status')
        require(status.get('testExecutionEnabled') is True, 'Worker unavailable')
        state = status['worker']
        require(state['deploymentSha256'] == policy_hash and state['sessionId'] == 0 and
                state['elevated'] is False and state['dedicatedAccount'] is True,
                'Current worker authority mismatch')
        require(re.fullmatch('[0-9a-f]{64}', state['epoch']), 'Invalid worker epoch')
        return state['epoch']

    epoch = worker()
    response = validation_client.operate(config, 'results', job)
    files, environment = verify(response, kind, policy_hash, policy, package, baseline)
    require(response['result']['workerEpoch'] == epoch and worker() == epoch, 'Worker changed during retrieval')
    require(all(read_authority(path) == data for path, data in snapshots), 'Local authority changed during retrieval')
    return response, files, environment
