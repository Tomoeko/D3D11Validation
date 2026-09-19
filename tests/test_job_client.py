#!/usr/bin/env python3
"""Result verification rejects stale or mismatched envelopes independently of SSH."""
import copy
import importlib.util
from pathlib import Path
import unittest
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


if __name__ == '__main__': unittest.main()
