import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('release', Path(__file__).parents[1] / 'client/build_headless_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def put_zip(path, content):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in content.items():
            archive.writestr(name, data)


class ReleaseTests(unittest.TestCase):
    def fixture(self, directory, mutation=None):
        members = {name: b'controlled fixture' for name in ('RuntimeProbe.exe', 'UnityPlayer.dll',
                    'RuntimeProbe_Data/globalgamemanagers', 'RuntimeProbe_Data/Managed/Assembly-CSharp.dll')}
        package = dict(schema='d3d11-unity-draw-package/v2', deployment='unity-draw-v5',
                       adapterSelection='unique-current-inventory',
                       files={k: hashlib.sha256(v).hexdigest() for k, v in members.items()})
        if mutation:
            mutation(members, package)
        content = {'Start-ValidationWorker.ps1': b'throw "test only"',
                   'unity-package.json': json.dumps(package).encode()}
        policy = dict(schema='d3d11-worker-policy/v1', executionContext='Session0',
                      files={k: hashlib.sha256(v).hexdigest() for k, v in content.items()})
        content['worker-policy.json'] = json.dumps(policy).encode()
        content['manifest.json'] = json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in content.items()}).encode()
        worker, unity, output = (directory / n for n in ('worker.zip', 'unity.zip', 'release.zip'))
        put_zip(worker, content)
        put_zip(unity, members)
        return worker, unity, output

    def test_manifest_bound_new_directories_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            worker, unity, output = self.fixture(Path(temporary))
            result = release.build(worker, 'worker-v22', output, unity)
            self.assertEqual(result['files'], 8)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual({n.split('/')[0] for n in archive.namelist()}, {'worker-v22', 'unity-draw-v5'})
            with self.assertRaises(FileExistsError):
                release.build(worker, 'worker-v22', output, unity)

    def test_unbound_or_unsafe_packages_rejected_before_publication(self):
        mutations = [
            lambda files, package: files.update({'unexpected.dll': b'extra'}),
            lambda files, package: files.update({'RuntimeProbe.exe': b'changed'}),
            lambda files, package: files.update({'../escape': b'extra'}),
            lambda files, package: files.update({'con.txt': b'extra'}),
            lambda files, package: files.update({'UNITYPLAYER.DLL': b'duplicate'}),
            lambda files, package: package.update(deployment='../existing'),
            lambda files, package: package.update(schema='d3d11-unity-draw-package/v1'),
            lambda files, package: package.update(adapterSelection='first-available'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                worker, unity, output = self.fixture(Path(temporary), mutation)
                with self.assertRaises(ValueError):
                    release.build(worker, 'worker-v22', output, unity)
                self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
