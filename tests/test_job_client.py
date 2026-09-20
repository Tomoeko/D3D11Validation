#!/usr/bin/env python3
"""Result verification rejects stale or mismatched envelopes independently of SSH."""
import copy
import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client/validation_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ResultBindingTests(unittest.TestCase):
    def setUp(self):
        self.job = dict(jobId='a'*32, capability='b'*64, inputSha256='c'*64,
                        deploymentSha256='d'*64, executionNonce='e'*64)
        self.result = {key: self.job[key] for key in ('jobId','inputSha256','deploymentSha256','executionNonce')}
        self.result['completion'] = 'completed'
        self.response = dict(self.job, state='completed', exitCode=0, result=self.result)

    def request(self, response):
        with patch.object(client, 'invoke', return_value=response):
            return client.operate(Path('unused'), 'results', self.job)

    def test_valid(self):
        self.assertEqual(self.request(self.response)['state'], 'completed')

    def test_each_binding(self):
        for key in ('jobId','inputSha256','deploymentSha256','executionNonce'):
            for target in ('envelope','result'):
                with self.subTest(key=key,target=target):
                    response = copy.deepcopy(self.response)
                    (response if target == 'envelope' else response['result'])[key] = 'f'*64
                    with self.assertRaises(ValueError): self.request(response)

    def test_incomplete(self):
        for replacement in (None, {}, {'completion':'running'}):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError): self.request(dict(self.response,result=replacement))
        with self.assertRaises(ValueError): self.request(dict(self.response,exitCode=1))

    def test_wire_replay_nonce(self):
        completed = type('Completed', (), dict(returncode=0,stdout=b'{"nonce":"old"}',stderr=b''))()
        with patch.object(client.subprocess, 'run', return_value=completed):
            with self.assertRaises(ValueError): client.invoke(Path('unused'),'status',{'nonce':'new'})

    def native_response(self):
        self.job['submitRequest'] = {'kind': 'device'}
        response = copy.deepcopy(self.response)
        artifacts = []
        for name, data in [('selection-adapters.json', b'{}'), ('adapters.json', b'{}'), ('report.json', b'{}'), ('pixels.bin', bytes(256))]:
            artifacts.append(dict(name=name, byteLength=len(data),
                                  sha256=hashlib.sha256(data).hexdigest(),
                                  base64=base64.b64encode(data).decode()))
        response['result']['fixture'] = {'artifacts': artifacts}
        return response

    def test_native_artifact_integrity(self):
        self.request(self.native_response())
        for key, value in [('byteLength', 17), ('sha256', '0'*64),
                           ('base64', 'invalid!'), ('name', '../private.json')]:
            with self.subTest(key=key):
                response = self.native_response()
                response['result']['fixture']['artifacts'][0][key] = value
                with self.assertRaises(ValueError): self.request(response)

    def test_missing_or_duplicate_native_artifacts(self):
        for change in ('missing_fixture', 'missing_file', 'duplicate_file'):
            with self.subTest(change=change):
                response = self.native_response()
                if change == 'missing_fixture': response['result']['fixture'] = None
                elif change == 'missing_file': response['result']['fixture']['artifacts'].pop()
                else: response['result']['fixture']['artifacts'].append(
                    copy.deepcopy(response['result']['fixture']['artifacts'][0]))
                with self.assertRaises(ValueError): self.request(response)

    def test_unity_artifact_sets(self):
        for mode in ('traced','untraced','unhooked'):
            self.job['submitRequest'] = {'kind':'unity-recovered-off-tier0-' + mode}
            response = copy.deepcopy(self.response)
            names = ['device.bin','result.tsv','pixels.bin','selection-adapters.json']
            if mode != 'unhooked': names.append('draws.bin')
            if mode == 'traced':
                names += [f'draw-{draw:04d}-{stage}.bin' for draw in (1,2) for stage in ('vs','ps')]
            artifacts = [dict(name=name,byteLength=0,sha256=hashlib.sha256(b'').hexdigest(),base64='')
                         for name in names]
            response['result']['fixture'] = dict(artifacts=artifacts)
            self.request(response)
            artifacts.pop()
            with self.assertRaises(ValueError): self.request(response)

    def test_unapproved_deployment_is_never_started(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'result.json'
            with patch.object(client,'submit',return_value=self.job), patch.object(client,'operate') as operation:
                with self.assertRaises(ValueError):
                    client.run_fixture(Path('unused'),'diagnostic','f'*64,output)
                operation.assert_not_called()
            self.assertTrue(output.with_suffix('.job.json').exists())
            self.assertFalse(output.exists())
            with self.assertRaises(FileExistsError):
                client.run_fixture(Path('unused'),'diagnostic','f'*64,output)

    def test_lost_worker_preserves_job_without_rerun(self):
        responses = [dict(executionNonce='e'*64), dict(recoveryRequired=True,state='running')]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'result.json'
            with patch.object(client,'submit',return_value=copy.deepcopy(self.job)) as submit, \
                 patch.object(client,'operate',side_effect=responses) as operation:
                with self.assertRaises(RuntimeError):
                    client.run_fixture(Path('unused'),'diagnostic','d'*64,output)
                self.assertEqual(submit.call_count,1)
                self.assertEqual([c.args[1] for c in operation.call_args_list],['start','status'])
            self.assertTrue(output.with_suffix('.job.json').exists())


if __name__ == '__main__': unittest.main()
