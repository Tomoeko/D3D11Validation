import copy
import hashlib
import json
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
from adapter_evidence import verify_selection


class AdapterEvidenceTests(unittest.TestCase):
    def setUp(self):
        pin = dict(name='Pinned GPU', vendorId=1234, deviceId=5678, subsystemId=10, revision=1, software=False)
        self.baseline = dict(schema='d3d11-native-environment-baseline/v4', adapterSelection='unique-current-inventory', adapter=pin)
        adapter = {k: v for k, v in pin.items() if k != 'software'}
        adapter.update(ordinal=0, luidLow=300, luidHigh=0, flags=0, dedicatedVideoMemory=1000)
        self.inventory = dict(schema='d3d11-adapter-inventory/v2', qualified=False, adapters=[adapter])
        self.policy = {'files': {'device-probe.exe': 'a' * 64}}
        boot = '2026-09-20T12:30:00.0000000Z'
        actual = dict(pin, luidLow=300, luidHigh=0)
        self.record = dict(session=dict(bootUtc=boot), fixture=dict(environment=dict(bootUtc=boot,
            adapter=actual, adapterSelection=dict(mode='unique-current-inventory', adapter=adapter,
                probeSha256='a' * 64, bootUtc=boot))))
        self.rebind()

    def rebind(self):
        data = json.dumps(self.inventory).encode()
        self.files = {'selection-adapters.json': data}
        self.record['fixture']['environment']['adapterSelection']['inventorySha256'] = hashlib.sha256(data).hexdigest()

    def test_current_boot_and_native_ordinal(self):
        verify_selection(self.record, self.files, self.baseline, self.policy)
        self.record['fixture']['environment']['adapter']['ordinal'] = 0
        verify_selection(self.record, self.files, self.baseline, self.policy)

    def test_stale_actual_or_boot_or_probe_rejected(self):
        for key, value in [('luidLow', 200), ('ordinal', 1), ('subsystemId', 9), ('software', True), ('software', 0), ('luidHigh', False)]:
            record = copy.deepcopy(self.record)
            record['fixture']['environment']['adapter'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_selection(record, self.files, self.baseline, self.policy)
        for location, key in [('session', 'bootUtc'), ('selection', 'probeSha256'), ('selection', 'inventorySha256')]:
            record = copy.deepcopy(self.record)
            target = record['session'] if location == 'session' else record['fixture']['environment']['adapterSelection']
            target[key] = 'incorrect'
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_selection(record, self.files, self.baseline, self.policy)

    def test_ambiguous_hardware_and_duplicate_luid_rejected(self):
        for low in (300, 301):
            self.inventory['adapters'] = [self.inventory['adapters'][0], dict(self.inventory['adapters'][0], ordinal=1, luidLow=low)]
            self.rebind()
            with self.subTest(low=low), self.assertRaises(ValueError):
                verify_selection(self.record, self.files, self.baseline, self.policy)

    def test_negative_and_string_and_software_inventory_rejected(self):
        for field, value in [('luidLow', -1), ('luidLow', '300'), ('luidLow', True), ('flags', 1), ('flags', 2), ('flags', 4)]:
            previous = self.inventory['adapters'][0][field]
            self.inventory['adapters'][0][field] = value
            self.rebind()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify_selection(self.record, self.files, self.baseline, self.policy)
            self.inventory['adapters'][0][field] = previous


if __name__ == '__main__': unittest.main()
