# SPDX-License-Identifier: GPL-3.0-only
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'client'))
import capture_unity as capture


class NativeCaptureTests(unittest.TestCase):
    def setUp(self):
        self.package = {'files': {'recovered.bundle': 'a' * 64,
                                 'regenerated.bundle': 'b' * 64,
                                 'selector-profile.bin': 'c' * 64}}
        self.package_bytes = json.dumps(self.package).encode()
        self.policy = {'files': {'unity-package.json': hashlib.sha256(self.package_bytes).hexdigest()}}
        self.policy_bytes = json.dumps(self.policy).encode()
        self.policy_hash = hashlib.sha256(self.policy_bytes).hexdigest()
        self.observations = [
            ({'jobId': str(index), 'deploymentSha256': self.policy_hash,
              'result': {'kind': kind, 'workerEpoch': 'd' * 64,
                         'fixture': {'environmentSha256': 'e' * 64}}},
             {name: bytes([index + 1]) for name in ('draw-0001-vs.bin', 'draw-0001-ps.bin',
                                                   'pixels.bin', 'result.tsv')})
            for index, kind in enumerate(capture.KINDS)]
        # Deliberately tiny artifact bytes exercise framing only. They cannot
        # pass the authenticated verifier or establish production authority.

    def encode(self, observations=None, package=None):
        return capture.encode_capture(self.policy_hash, self.package_bytes,
                                      package or self.package,
                                      self.observations if observations is None else observations,
                                      'a' * 64, 'b' * 64)

    def test_framing_preserves_order_and_complete_bytes(self):
        data = self.encode()
        self.assertEqual(data[:8], b'DVUOBS01')
        self.assertEqual(struct.unpack_from('<III', data, 8), (1, 3, 12))
        self.assertEqual(data[20:52], bytes.fromhex(self.policy_hash))
        self.assertEqual(data[52:84], hashlib.sha256(self.package_bytes).digest())
        position = 212
        names = []
        for _ in range(3):
            size, = struct.unpack_from('<I', data, position)
            position += 4
            name = data[position:position + size].decode()
            position += size
            self.assertEqual(data[position:position + 32], bytes.fromhex(self.package['files'][name]))
            position += 32
            names.append(name)
        self.assertEqual(names, sorted(self.package['files']))
        for index in range(12):
            self.assertNotEqual(data[position:position + 32], bytes(32))
            position += 32
            for _ in range(4):
                size, = struct.unpack_from('<I', data, position)
                position += 4
                self.assertEqual(data[position:position + size], bytes([index + 1]))
                position += size
        self.assertEqual(position, len(data))

    def test_split_and_incomplete_authorities_rejected(self):
        for count in (0, 11, 13):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.encode((self.observations * 2)[:count])
        for field, value in (('kind', capture.KINDS[0]), ('workerEpoch', 'f' * 64)):
            changed = copy.deepcopy(self.observations)
            changed[1][0]['result'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.encode(changed)
        for where, field in (('result', 'environmentSha256'), ('outer', 'jobId'),
                             ('outer', 'deploymentSha256')):
            changed = copy.deepcopy(self.observations)
            if where == 'result': changed[1][0]['result']['fixture'][field] = 'f' * 64
            else: changed[1][0][field] = changed[0][0]['jobId'] if field == 'jobId' else 'f' * 64
            with self.subTest(field=field), self.assertRaises(ValueError): self.encode(changed)

    def test_bound_paths_digests_and_artifact_sizes(self):
        for name in ('../escape', '/absolute', 'a\\b', 'a//b', 'a/./b', 'a\x00b', 'x' * 4097):
            changed = copy.deepcopy(self.package)
            changed['files'][name] = 'a' * 64
            with self.subTest(name=name[:20]), self.assertRaises(ValueError): self.encode(package=changed)
        for value in ('A' * 64, 'x' * 64, 'a' * 63):
            changed = copy.deepcopy(self.package)
            changed['files']['selector-profile.bin'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.encode(package=changed)
        for value in (b'', bytes(65537)):
            changed = copy.deepcopy(self.observations)
            changed[0][1]['pixels.bin'] = value
            with self.assertRaises(ValueError): self.encode(changed)
        changed = copy.deepcopy(self.observations)
        for _, files in changed:
            for name in files: files[name] = bytes(65536)
        with self.assertRaises(ValueError): self.encode(changed)

    def test_collector_requires_fresh_retrieval_for_every_job(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy = root / 'worker-policy.json'
            package = root / 'unity-package.json'
            jobs = root / 'jobs.json'
            policy.write_bytes(self.policy_bytes)
            package.write_bytes(self.package_bytes)
            jobs.write_text(json.dumps([{'submitRequest': {'kind': kind}} for kind in reversed(capture.KINDS)]))
            index = 0

            def retrieve(config, job, policy_path, expected):
                nonlocal index
                self.assertEqual(policy_path, policy)
                self.assertEqual(job['submitRequest']['kind'], capture.KINDS[index])
                self.assertEqual(expected, ('b' if index % 2 else 'a') * 64)
                response, files = self.observations[index]
                index += 1
                return response, files, 'e' * 64

            with patch.object(capture, 'retrieve_verified', side_effect=retrieve):
                self.assertEqual(capture.collect(root / 'config', policy, jobs, 'a' * 64, 'b' * 64),
                                 self.encode())
            self.assertEqual(index, 12)
            with patch.object(capture, 'retrieve_verified', side_effect=RuntimeError('transport')):
                with self.assertRaises(RuntimeError):
                    capture.collect(root / 'config', policy, jobs, 'a' * 64, 'b' * 64)
            jobs.write_text(json.dumps([{'submitRequest': {'kind': capture.KINDS[0]}}] * 12))
            with patch.object(capture, 'retrieve_verified') as called:
                with self.assertRaises(ValueError):
                    capture.collect(root / 'config', policy, jobs, 'a' * 64, 'b' * 64)
                called.assert_not_called()


if __name__ == '__main__':
    unittest.main()
