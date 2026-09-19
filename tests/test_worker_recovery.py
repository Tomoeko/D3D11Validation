"""Prove a rejected fixture terminates only its job and leaves the worker usable."""
import argparse
import importlib.util
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def run(config, output, kind):
    job = client.submit(config, kind=kind)
    client.save(output.with_suffix('.job.json'), job)
    started = client.operate(config, 'start', job)
    job['executionNonce'] = started['executionNonce']
    client.save(output.with_suffix('.job.json'), job)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        state = client.operate(config, 'status', job)
        if state.get('recoveryRequired'): raise RuntimeError('Worker was lost')
        if state['state'] in ('completed', 'failed', 'stale', 'cancelled', 'timed_out'):
            result = client.operate(config, 'results', job)
            client.save(output, result)
            return job, result
        time.sleep(.1)
    raise TimeoutError('Job did not terminate')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-config', type=Path, default=Path('.local/ssh_config'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Evidence output already exists')
    before = client.invoke(args.ssh_config, 'status')['worker']
    job, rejected = run(args.ssh_config, args.output.with_suffix('.rejected.json'), 'reject-session')
    assert rejected['state'] == 'failed' and rejected['exitCode'] is None
    result = rejected['result']
    assert result['failureCode'] == 'unapproved_session'
    assert result['childPid'] is None and result['binarySha256'] is None
    assert result['session']['dedicatedAccount'] and not result['session']['elevated']
    assert result['workerEpoch'] == before['epoch']
    repeated = client.operate(args.ssh_config, 'start', job)
    assert repeated['state'] == 'failed' and repeated['executionNonce'] == job['executionNonce']
    _, positive = run(args.ssh_config, args.output.with_suffix('.positive.json'), 'diagnostic')
    assert positive['state'] == 'completed' and positive['exitCode'] == 0
    after = client.invoke(args.ssh_config, 'status')['worker']
    assert before['epoch'] == after['epoch'] == positive['result']['workerEpoch']
    client.save(args.output, dict(schema='d3d11-worker-recovery/v1',
        rejectedBeforeLaunch=True, rejectedJobCannotRestart=True,
        subsequentDiagnosticPassed=True, sameWorkerSurvived=True))
    print('PASS: pre-launch rejection is terminal; the same worker completes the next job')


if __name__ == '__main__': main()
