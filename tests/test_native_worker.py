#!/usr/bin/env python3
"""Accept a bounded native clear/readback campaign against a pinned deployment."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('client', ROOT/'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def verify(result, kind, policy_hash, binary_hash, baseline, session_state):
    assert result['deploymentSha256'] == policy_hash
    record = result['result']
    assert record['binarySha256'] == binary_hash and record['failureCode'] is None
    fixture = record['fixture']
    files = {item['name']:base64.b64decode(item['base64'],validate=True) for item in fixture['artifacts']}
    if kind != 'device':
        assert result['state'] == 'failed' and result['exitCode'] == 1
        assert set(files) == {'adapters.json'} and fixture['environment'] is None
        return
    assert result['state'] == 'completed' and result['exitCode'] == 0
    assert files['pixels.bin'] == struct.pack('<4f',.25,.5,.75,1) * 16
    report = json.loads(files['report.json'])
    env = fixture['environment']
    expected_adapter = dict(baseline['adapter'],ordinal=report['adapter']['ordinal'])
    assert env['adapter'] == expected_adapter, 'Adapter identity drift'
    for key in ('featureLevel','creationFlags','operatingSystem'):
        assert env[key] == baseline[key], 'Environment drift: ' + key
    assert len(env['runtimeIdentities']) == len(baseline['runtimeIdentities'])
    for identity, pinned in zip(env['runtimeIdentities'], baseline['runtimeIdentities']):
        for field in ('file','version','sha256'):
            assert identity[field] == pinned[field], 'Runtime identity drift: ' + field
        assert identity['signatureStatus'] == 'Valid'
        observed_signature = dict(type=identity['signatureType'], signer=identity['signer'],
                                  certificateSha256=identity['certificateSha256'])
        assert observed_signature in pinned['signatures'], 'Unapproved runtime certificate'
    assert env['processSessionId'] == baseline['allowedSessionId']
    assert env['executionContext'] == baseline['executionContext'] == report['executionContext']
    assert env['clientProtocolType'] == baseline['sessionProtocolsByConnectionState'][str(session_state)]
    assert env['connectionState'] == session_state == report['connectionState']
    assert env['nativeHardwarePreflightPassed'] and not env['fullQualificationComplete']
    assert report['adapter'] == env['adapter'] and report['sessionId'] == env['processSessionId']
    assert not report['elevated'] and report['bitwiseReferenceMatch']
    # PowerShell emits this ordered ASCII object without extra whitespace.
    canonical = json.dumps(env,separators=(',',':'),ensure_ascii=False).encode()
    assert hashlib.sha256(canonical).hexdigest() == fixture['environmentSha256']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config',type=Path,default=Path('.local/ssh_config'))
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--session-state',type=int,choices=(-1,0,4),required=True)
    parser.add_argument('--positive-only',action='store_true')
    args = parser.parse_args()
    if args.output.exists(): parser.error('Evidence output already exists')
    policy = json.loads(args.policy.read_text())
    policy_hash = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    baseline = json.loads(args.policy.with_name('native-baseline.json').read_text())
    results = []
    kinds = ['device','device'] + ([] if args.positive_only else ['reject-software','reject-other-gpu'])
    for kind in kinds:
        job = client.submit(args.ssh_config,kind=kind)
        client.save(args.output.with_suffix('.job-' + str(len(results)) + '.json'), job)
        started = client.operate(args.ssh_config,'start',job)
        job['executionNonce'] = started['executionNonce']
        client.save(args.output.with_suffix('.job-' + str(len(results)) + '.json'), job)
        deadline = time.monotonic()+30
        while True:
            status = client.operate(args.ssh_config,'status',job)
            if status.get('recoveryRequired'): raise RuntimeError('Worker unavailable; preserve this job for recovery')
            state = status['state']
            if state in ('completed','failed','cancelled','timed_out','stale'): break
            if time.monotonic()>deadline: raise TimeoutError('Native fixture did not finish')
            time.sleep(.1)
        result = client.operate(args.ssh_config,'results',job)
        results.append(result)
        client.save(args.output,{'schema':'d3d11-native-worker-campaign/v1','sessionState':args.session_state,
                    'deploymentSha256':policy_hash,'results':results,'campaignAccepted':False,'fullQualificationComplete':False})
        verify(result,kind,policy_hash,policy['files']['device-probe.exe'],baseline,args.session_state)
        print('PASS:',kind,flush=True)
    assert results[0]['result']['fixture']['environmentSha256'] == results[1]['result']['fixture']['environmentSha256']
    client.save(args.output,{'schema':'d3d11-native-worker-campaign/v1','sessionState':args.session_state,
                            'deploymentSha256':policy_hash,'results':results,'campaignAccepted':True,'fullQualificationComplete':False})
    print('PASS: native worker campaign, repeated raw bytes, pinned environment and rejection controls')


if __name__ == '__main__': main()
