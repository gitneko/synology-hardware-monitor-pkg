"""Reject stale/mixed build identities before producing an installable package."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('build_packages', Path(__file__).parents[1]/'build_packages.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BuildVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'web').mkdir(); (self.root/'packaging').mkdir()
        (self.root/'Cargo.toml').write_text('[package]\nname="hardware-monitor"\nversion="0.9.0"\n')
        (self.root/'Cargo.lock').write_text('[[package]]\nname="hardware-monitor"\nversion="0.9.0"\n')
        (self.root/'packaging/INFO.dsm7').write_text('version="0.9.0-0050"\n')
        (self.root/'web/package.json').write_text(json.dumps({'version':'0.9.0'}))
        self.lock = {'version':'0.9.0','packages':{'':{'version':'0.9.0'}}}
        self.write_lock()

    def write_lock(self):
        (self.root/'web/package-lock.json').write_text(json.dumps(self.lock))

    def test_matching_product_frontend_and_package_are_accepted(self):
        self.assertEqual(module.version_metadata(self.root), '0.9.0-0050')

    def test_stale_frontend_and_root_locks_are_rejected(self):
        for target in ('package', 'lock', 'lock-package', 'cargo-lock'):
            with self.subTest(target=target):
                original = {p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
                if target == 'package':
                    (self.root/'web/package.json').write_text('{"version":"0.8.0"}')
                elif target == 'lock':
                    self.lock['version'] = '0.8.0'; self.write_lock()
                elif target == 'lock-package':
                    self.lock['packages']['']['version'] = '0.8.0'; self.write_lock()
                else:
                    (self.root/'Cargo.lock').write_text('[[package]]\nname="hardware-monitor"\nversion="0.8.0"\n')
                with self.assertRaisesRegex(ValueError, 'version mismatch'):
                    module.version_metadata(self.root)
                for path, contents in original.items():
                    path.write_bytes(contents)
                self.lock = json.loads((self.root/'web/package-lock.json').read_text())

    def test_wrong_semver_or_invalid_package_counter_is_rejected(self):
        for version in ('0.8.0-0050', '0.9.0', '0.9.0-50', '0.9.0-0050-other'):
            with self.subTest(version=version):
                (self.root/'packaging/INFO.dsm7').write_text(f'version="{version}"\n')
                with self.assertRaisesRegex(ValueError, 'version mismatch'):
                    module.version_metadata(self.root)
