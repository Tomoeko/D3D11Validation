# SPDX-License-Identifier: GPL-3.0-only
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'client'))
import unity_evidence as evidence


class PlayerRecordTests(unittest.TestCase):
    def setUp(self):
        self.pixels = bytes(256)
        self.package = {'files': {
            'recovered.bundle': 'a' * 64,
            'RuntimeProbe_Data/globalgamemanagers': 'b' * 64,
            'RuntimeProbe_Data/Managed/Assembly-CSharp.dll': 'c' * 64,
        }}
        self.kind = 'unity-recovered-off-tier0-traced'
        self.record = (
            'schema\tdxbc-private-player-draw-domain/v3\n'
            'instrumentation\ton\nbundle_sha256\t' + 'a' * 64 + '\n'
            'player_metadata_sha256\t' + 'b' * 64 + '\n'
            'harness_path\tC:\\Approved\\Assembly-CSharp.dll\nharness_sha256\t' + 'c' * 64 + '\n'
            'unity_version\t2021.3.35f1\nbackend\tDirect3D11\ndevice\tControlled GPU\ndriver\tControlled Driver\n'
            'render_threading\tDirect\nfog_enabled\tFalse\nfog_mode\tLinear\n'
            'fog_input_float32le\t0000803e0000003f0000403f0000803f00000000000096430ad7233c\n'
            'active_tier_enum\t0\ncolor_space\tGamma\nasset\tassets/fixture.shader\n'
            'shader\tExample/UV\nsupported\tTrue\n'
            'keyword_decl\tSTEREO_INSTANCING_ON:True\nkeyword_decl\tUNITY_SINGLE_PASS_STEREO:True\n'
            'keyword_decl\tSTEREO_MULTIVIEW_ON:True\nkeyword_decl\tSTEREO_CUBEMAP_RENDER_ON:True\n'
            'keyword_decl\tUV_VARIANT:True\npass_count\t1\npass_name\tUV\n'
            'uv_variant_enabled\tFalse\nmaterial_keyword_count\t0\nmesh\tcanonical-quad-position-identity-v1\n'
            'render_target\t4x4-rgba32f-linear-depth24-msaa1\npixel_bytes\t256\n'
            'pixels_sha256\t' + hashlib.sha256(self.pixels).hexdigest() + '\n'
            'repeated_pixels_equal\tTrue\nset_pass\tTrue\n')

    def verify(self, text):
        return evidence.verify_player_record(text.encode(), self.kind, self.package, self.pixels)

    def test_observed_artifact_and_inputs(self):
        self.assertEqual(self.verify(self.record)['bundle_sha256'], 'a' * 64)
        for before, after in [
            ('a' * 64, 'd' * 64), ('b' * 64, 'e' * 64), ('c' * 64, 'f' * 64),
            ('backend\tDirect3D11', 'backend\tVulkan'), ('active_tier_enum\t0', 'active_tier_enum\t1'),
            ('render_threading\tDirect', 'render_threading\tMultiThreaded'),
            ('material_keyword_count\t0', 'material_keyword_count\t1'),
            ('uv_variant_enabled\tFalse', 'uv_variant_enabled\tTrue'),
            ('fog_enabled\tFalse', 'fog_enabled\tTrue'), ('instrumentation\ton', 'instrumentation\toff'),
            ('pixel_bytes\t256', 'pixel_bytes\t255'), ('set_pass\tTrue', 'set_pass\tFalse'),
            ('UV_VARIANT:True', 'UV_VARIANT:False'),
            (hashlib.sha256(self.pixels).hexdigest(), '0' * 64),
        ]:
            with self.subTest(field=before.split('\t')[0]), self.assertRaises(ValueError):
                self.verify(self.record.replace(before, after))

    def test_ambiguous_or_incomplete_records(self):
        for text in [self.record + 'backend\tDirect3D11\n',
                     self.record + 'keyword_decl\tUV_VARIANT:True\n',
                     self.record + 'unknown\tvalue\n', self.record + 'malformed\n',
                     self.record.replace('backend\tDirect3D11\n', ''),
                     self.record.replace('shader\tExample/UV', 'shader\t'),
                     self.record.replace('Example/UV', 'Example\x00UV'), 'a' * 65537]:
            with self.subTest(record=text[-50:]), self.assertRaises(ValueError):
                self.verify(text)


class AuthenticatedRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'worker-policy.json'
        self.package = {'files': {'recovered.bundle': 'a' * 64}}
        files = {}
        for name, value in [('unity-package.json', self.package), ('native-baseline.json', {})]:
            data = json.dumps(value).encode()
            self.path.with_name(name).write_bytes(data)
            files[name] = evidence.digest(data)
        self.path.write_text(json.dumps(dict(schema='d3d11-worker-policy/v1', executionContext='Session0', files=files)))
        self.policy_hash = evidence.digest(self.path.read_bytes())
        self.job = dict(deploymentSha256=self.policy_hash, submitRequest=dict(kind='unity-recovered-off-tier0-traced'))
        self.worker = dict(testExecutionEnabled=True, worker=dict(deploymentSha256=self.policy_hash,
            sessionId=0, elevated=False, dedicatedAccount=True, epoch='e' * 64))
        self.response = {'result': {'workerEpoch': 'e' * 64}}

    def retrieve(self):
        return evidence.retrieve_verified(Path('unused-config'), self.job, self.path, 'a' * 64)

    def test_only_authenticated_response_reaches_verifier(self):
        with patch.object(evidence.validation_client, 'invoke', return_value=self.worker) as status, \
             patch.object(evidence.validation_client, 'operate', return_value=self.response) as operation, \
             patch.object(evidence, 'verify', return_value=({}, 'environment')) as verify:
            self.assertEqual(self.retrieve()[0], self.response)
            self.assertEqual(status.call_count, 2)
            operation.assert_called_once_with(Path('unused-config'), 'results', self.job)
            self.assertIs(verify.call_args.args[0], self.response)

    def test_wrong_bundle_or_policy_never_retrieved(self):
        with patch.object(evidence.validation_client, 'operate') as operation:
            with self.assertRaises(ValueError):
                evidence.retrieve_verified(Path('unused'), self.job, self.path, 'b' * 64)
            self.path.with_name('unity-package.json').write_text('{}')
            with self.assertRaises(ValueError):
                self.retrieve()
            operation.assert_not_called()

    def test_stale_epoch_and_worker_change(self):
        with patch.object(evidence.validation_client, 'invoke', return_value=self.worker), \
             patch.object(evidence.validation_client, 'operate', return_value={'result': {'workerEpoch': 'f' * 64}}), \
             patch.object(evidence, 'verify', return_value=({}, 'environment')):
            with self.assertRaises(ValueError): self.retrieve()
        changed = dict(self.worker, worker=dict(self.worker['worker'], epoch='f' * 64))
        with patch.object(evidence.validation_client, 'invoke', side_effect=[self.worker, changed]), \
             patch.object(evidence.validation_client, 'operate', return_value=self.response), \
             patch.object(evidence, 'verify', return_value=({}, 'environment')):
            with self.assertRaises(ValueError): self.retrieve()

    def test_transport_failure_is_not_retried_as_an_execution(self):
        with patch.object(evidence.validation_client, 'invoke', return_value=self.worker), \
             patch.object(evidence.validation_client, 'operate', side_effect=RuntimeError('transport_failed')) as operation:
            with self.assertRaises(RuntimeError): self.retrieve()
            self.assertEqual(operation.call_count, 1)

    def test_local_authority_drift(self):
        def mutate(*args):
            self.path.with_name('native-baseline.json').write_text('{"changed":true}')
            return {}, 'environment'
        with patch.object(evidence.validation_client, 'invoke', return_value=self.worker), \
             patch.object(evidence.validation_client, 'operate', return_value=self.response), \
             patch.object(evidence, 'verify', side_effect=mutate):
            with self.assertRaises(ValueError): self.retrieve()


if __name__ == '__main__':
    unittest.main()
