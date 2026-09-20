import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import time

SPEC = importlib.util.spec_from_file_location('headless', Path(__file__).parents[1] / 'client/headless_client.py')
headless = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(headless)


class HeadlessClientTests(unittest.TestCase):
    def setUp(self):
        self.status = {'active': dict(schema='d3d11-active-deployment/v1', generation=1,
                                     deployment='worker-v20', policySha256='a' * 64)}

    def test_actions_preserve_active_binding(self):
        for action in ('repair', 'archive'):
            request = headless.request(action, self.status)
            self.assertEqual(request['generation'], '1')
            self.assertEqual(request['expectedPolicy'], 'a' * 64)
            self.assertEqual(request['deployment'], '-')
            self.assertEqual(len(request['requestId']), 32)

    def test_invalid_actions_and_active_state(self):
        for action in ('shell', 'remove', 'reboot', 'activate'):
            with self.assertRaises(ValueError):
                headless.request(action, self.status)
        for generation in (0, True, '1', 999999999):
            self.status['active']['generation'] = generation
            with self.assertRaises(ValueError):
                headless.request('repair', self.status)

    def test_publication_has_no_arbitrary_url(self):
        publication = dict(deployment='worker-v21', policySha256='b' * 64, archiveSha256='c' * 64,
                           archiveBytes=100, port=4433, ticket='d' * 48, certificateSha256='e' * 64)
        value = headless.request('activate', self.status, publication)
        self.assertNotIn('url', value)
        self.assertEqual(value['port'], '4433')
        for key, bad in (('deployment', '../a'), ('policySha256', 'x'), ('port', 65536),
                         ('ticket', '/a'), ('archiveBytes', 268435457)):
            changed = dict(publication, **{key: bad})
            with self.assertRaises(ValueError):
                headless.request('activate', self.status, changed)
        with self.assertRaises(ValueError):
            headless.request('repair', self.status, publication)

    def test_receipt_binds_exact_signed_request(self):
        value = headless.request('repair', self.status)
        receipt = dict(schema='d3d11-maintenance-receipt/v1', requestId=value['requestId'],
                       requestSha256=hashlib.sha256(headless.encode(value)).hexdigest(), phase='queued')
        headless.verify_receipt(receipt, value)
        for key, bad in (('requestId', '0' * 32), ('requestSha256', '0' * 64),
                         ('schema', 'unknown'), ('phase', 'executing-shell')):
            with self.assertRaises(ValueError):
                headless.verify_receipt(dict(receipt, **{key: bad}), value)

    def test_uncertain_response_retries_identical_envelope(self):
        value = headless.request('repair', self.status)
        receipt = dict(schema='d3d11-maintenance-receipt/v1', requestId=value['requestId'],
                       requestSha256=hashlib.sha256(headless.encode(value)).hexdigest(), phase='completed')
        envelope = {'request': 'unchanged', 'signature': 'unchanged'}
        with patch.object(headless, 'invoke', side_effect=[RuntimeError('lost'), RuntimeError('lost'), receipt]) as invoke, \
             patch.object(headless.time, 'sleep'):
            self.assertEqual(headless.retrieve_receipt(Path('config'), envelope, value, time.monotonic() + 60), receipt)
            self.assertEqual(invoke.call_count, 3)
            for call in invoke.call_args_list:
                self.assertIs(call.args[2], envelope)
        with patch.object(headless, 'invoke', side_effect=RuntimeError('offline')) as invoke, \
             patch.object(headless.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                headless.retrieve_receipt(Path('config'), envelope, value, time.monotonic() + 60)
            self.assertEqual(invoke.call_count, 3)


if __name__ == '__main__':
    unittest.main()
