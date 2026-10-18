"""Release safety checks with a fake GitHub client; never publish anything."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('publish_latest', Path(__file__).parents[1]/'publish_latest.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHA = '1'*40


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        packages = {}
        for name in sorted(module.NAMES):
            if name.endswith('.spk'):
                (self.root/name).write_bytes(b'synthetic package')
                packages[name] = hashlib.sha256(b'synthetic package').hexdigest()
        (self.root/'build-manifest.json').write_text(json.dumps({'commit': SHA, 'version': '0.8.0-0018', 'packages': packages}))
        self.sums()
        self.calls = []
        self.head = SHA
        self.release = {'immutable': False, 'assets': [{'name': 'HardwareMonitor-0.8.0-0017-v1000-dsm7-development.spk'}, {'name': 'HardwareMonitorNotifyProbe.spk'}, {'name': 'user-notes.txt'}]}
        self.tag = {'object': {'sha': '2'*40}}

    def sums(self):
        files = sorted(p for p in self.root.iterdir() if p.name != 'SHA256SUMS')
        (self.root/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))

    def client(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == 'api' and '/git/ref/heads/' in args[1]:
            return {'object': {'sha': self.head}}
        if args[:2] == ('api', 'repos/owner/repo/releases/tags/latest'):
            return self.release
        if args[:2] == ('api', 'repos/owner/repo/git/ref/tags/latest'):
            return self.tag
        return {}

    def publish(self):
        return module.publish(self.root, 'owner/repo', SHA, 'main', self.client)

    def test_replace_keeps_unrelated_assets_and_moves_source_tag(self):
        self.assertTrue(self.publish())
        patch = next(kw['payload'] for args, kw in self.calls if args[:3] == ('api', '--method', 'PATCH'))
        self.assertEqual(patch, {'sha': SHA, 'force': True})
        upload = next(args for args, _ in self.calls if args[:2] == ('release', 'upload'))
        self.assertIn('--clobber', upload)
        deleted = [args[3] for args, _ in self.calls if args[:2] == ('release', 'delete-asset')]
        self.assertEqual(deleted, ['HardwareMonitor-0.8.0-0017-v1000-dsm7-development.spk'])

    def test_first_release_creates_tag_and_attaches_all_assets(self):
        self.release = self.tag = None
        self.assertTrue(self.publish())
        create = next(args for args, _ in self.calls if args[:2] == ('release', 'create'))
        self.assertIn('--verify-tag', create)
        self.assertIn('--prerelease', create)
        self.assertEqual(sum(str(self.root/name) in create for name in module.NAMES), 4)

    def test_superseded_build_has_no_writes(self):
        self.head = '2'*40
        self.assertFalse(self.publish())
        self.assertEqual(len(self.calls), 1)

    def test_immutable_release_has_no_writes(self):
        self.release['immutable'] = True
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.publish()
        self.assertEqual(len(self.calls), 2)

    def test_tampered_asset_rejected_before_network(self):
        (self.root/'HardwareMonitor-dsm7-x86_64.spk').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.publish()
        self.assertFalse(self.calls)

    def test_wrong_commit_rejected_before_network(self):
        manifest = self.root/'build-manifest.json'
        data = json.loads(manifest.read_text()); data['commit'] = '2'*40
        manifest.write_text(json.dumps(data)); self.sums()
        with self.assertRaisesRegex(ValueError, 'commit mismatch'):
            self.publish()
        self.assertFalse(self.calls)

    def test_failed_upload_does_not_edit_notes_or_delete_old_assets(self):
        def fail(*args, **kwargs):
            if args[:2] == ('release', 'upload'):
                raise RuntimeError('simulated failure')
            return self.client(*args, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'simulated'):
            module.publish(self.root, 'owner/repo', SHA, 'main', fail)
        self.assertFalse(any(args[:2] == ('release', 'delete-asset') for args, _ in self.calls))
