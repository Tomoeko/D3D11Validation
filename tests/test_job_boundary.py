#!/usr/bin/env python3
"""Live diagnostic acceptance; run only against the reviewed SSH alias."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import time

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
TERMINAL = {'completed','cancelled','timed_out','failed','stale'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--session-id', type=int, required=True, help='Exact worker session expected for this campaign')
    args = parser.parse_args()
    checks = []
    raw = []
    def passed(name):
        checks.append({'test':name,'passed':True})
        print('PASS:', name, flush=True)
    def reject(operation, request, expected=None):
        try: client.invoke(args.ssh_config, operation, request)
        except RuntimeError as failure:
            if expected is not None and str(failure) != expected: raise
            return
        raise AssertionError('Unexpected accepted request')
    def finish(job):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = client.operate(args.ssh_config, 'status', job)
            if status['state'] in TERMINAL:
                result = client.operate(args.ssh_config, 'results', job)
                raw.append(result)
                return result
            time.sleep(.1)
        raise AssertionError('Job did not finish')
    def start(job):
        response = client.operate(args.ssh_config, 'start', job)
        job['executionNonce'] = response['executionNonce']
        return response
    status = client.invoke(args.ssh_config,'status')
    assert status['allowedOperations'] == ['submit','start','status','results','cancel']
    assert status['worker']['sessionId'] == args.session_id and not status['worker']['elevated']
    passed('expected_standard_worker_session')
    job = client.submit(args.ssh_config,0)
    same = client.invoke(args.ssh_config,'submit',job['submitRequest'])
    assert all(same[key] == job[key] for key in ('jobId','capability','inputSha256'))
    passed('idempotent_submit')
    reject('submit',dict(job['submitRequest'],durationMs='1'),'nonce_conflict')
    passed('conflicting_nonce_rejected')
    request = dict(version='1',nonce=secrets.token_hex(32),jobId=job['jobId'],capability=job['capability'])
    reject('results',request,'results_incomplete')
    passed('incomplete_results_rejected')
    reject('status',dict(request,capability='0'*64),'job_unavailable')
    reject('status',dict(request,jobId='0'*32),'job_unavailable')
    passed('unrelated_job_access_rejected')
    start(job)
    result = finish(job)
    assert result['state'] == 'completed' and result['result']['binarySha256']
    repeated = client.operate(args.ssh_config,'start',job)
    assert repeated['executionNonce'] == job['executionNonce'] and repeated['state'] == 'completed'
    passed('start_status_results_and_no_reexecution')
    another = client.submit(args.ssh_config,0)
    start(another)
    assert finish(another)['state'] == 'completed'
    passed('repeat_positive_diagnostic')
    timeout = client.submit(args.ssh_config,5000)
    start(timeout)
    assert finish(timeout)['state'] == 'timed_out'
    passed('owned_process_timeout')
    cancelled = client.submit(args.ssh_config,5000)
    start(cancelled)
    client.operate(args.ssh_config,'cancel',cancelled)
    assert finish(cancelled)['state'] == 'cancelled'
    passed('running_job_cancel')
    pending = client.submit(args.ssh_config,0)
    client.operate(args.ssh_config,'cancel',pending)
    assert finish(pending)['state'] == 'cancelled'
    assert client.operate(args.ssh_config,'start',pending)['state'] == 'cancelled'
    passed('pending_job_cancel_is_terminal')
    invalid = [
        dict(job['submitRequest'],path='../secret'),
        dict(job['submitRequest'],script='powershell'),
        dict(job['submitRequest'],executable='cmd'),
        dict(job['submitRequest'],kind='shell'),
        dict(job['submitRequest'],durationMs='5001'),
        dict(request,jobId='../secret'),
        dict(request,jobId='A'*32),
        dict(request,filename='private'),
        dict(request,version='2'),
    ]
    for i, item in enumerate(invalid): reject('submit' if i < 5 else 'results',item)
    passed('unapproved_code_paths_and_fields_rejected')
    for payload in (b'{', b'{}', b'{} trailing', b'\0', b'a'*8193,
                    b'{"version":"1","version":"1"}', b'{"version":1}'):
        completed = subprocess.run(['ssh','-F',str(args.ssh_config),'d3d11-validation','submit'],input=payload,capture_output=True,timeout=25)
        assert completed.returncode != 0 and not completed.stdout
    passed('malformed_duplicate_and_oversized_rejected')
    # Interrupt a submission before a complete JSON body. The retry uses the same
    # nonce and must create exactly one usable job despite the lost SSH session.
    nonce = secrets.token_hex(32)
    request = dict(version='1',nonce=nonce,kind='diagnostic',durationMs='0')
    interrupted = subprocess.Popen(['ssh','-F',str(args.ssh_config),'d3d11-validation','submit'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    interrupted.stdin.write(client.encode(request)[:40]); interrupted.stdin.flush()
    time.sleep(.2); interrupted.kill(); interrupted.communicate(timeout=5)
    retry = client.submit(args.ssh_config,0,nonce)
    start(retry)
    assert finish(retry)['state'] == 'completed'
    passed('interrupted_submission_and_reconnect')
    client.save(args.output,{'schema':'d3d11-job-boundary/v1','expectedSessionId':args.session_id,'checks':checks,'results':raw})
    print('PASS:',len(checks),'live job checks; raw evidence saved to ignored output')


if __name__ == '__main__': main()
