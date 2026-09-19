"""Verify the generated SSH entry point preserves the child's process status."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('deployment', Path(__file__).parents[1] / 'client/build_deployment.py')
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class GatewayEntryTests(unittest.TestCase):
    def test_exit_status_propagation(self):
        powershell = shutil.which('pwsh') or shutil.which('powershell')
        if not powershell:
            self.skipTest('PowerShell is required for process-level exit-status verification')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / 'worker-v4' / 'Invoke-ValidationJobGateway.ps1'
            child.parent.mkdir()
            entry = root / 'gateway.ps1'
            entry.write_bytes(deployment.gateway_entry('worker-v4'))
            for status in (0, 64):
                with self.subTest(status=status):
                    child.write_text('exit ' + str(status) + '\n')
                    result = subprocess.run([powershell, '-NoProfile', '-File', str(entry)],
                                            capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, status)

    def test_untrusted_deployment_path_rejected(self):
        for name in ('../worker-v4', "worker-v4'); exit 0; #", 'worker-v4/extra', 'worker-v0', 'worker-v4\n'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError): deployment.gateway_entry(name)


if __name__ == '__main__': unittest.main()
