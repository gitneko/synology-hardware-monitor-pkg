"""Execute uninstall hooks and both DSM wizard formats in disposable directories."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from uninstall_wizard import write_wizards


class UninstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.assets.cleanup)
        directory = Path(cls.assets.name)
        # check_spk runs these same behavioral checks on the actual shipped files.
        package = os.environ.get('HARDWARE_MONITOR_TEST_SPK')
        if package:
            with tarfile.open(package) as archive:
                cls.hook = archive.extractfile('scripts/postuninst').read().decode()
                cls.wizards = {
                    name.rsplit('/', 1)[-1]: archive.extractfile(name).read().decode()
                    for name in archive.getnames()
                    if name.startswith('WIZARD_UIFILES/') and name.endswith('.sh')
                }
        else:
            cls.hook = (ROOT/'packaging/scripts/postuninst').read_text()
            write_wizards(directory/'wizard')
            cls.wizards = {p.name: p.read_text() for p in (directory/'wizard').iterdir()}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hardware-monitor-uninstall-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root/'volume1/@appconf/HardwareMonitor'
        self.config.mkdir(parents=True)
        self.package = self.root/'var/packages/HardwareMonitor'
        self.package.mkdir(parents=True)
        (self.package/'etc').symlink_to(self.config, target_is_directory=True)
        for name in ['private/monitor.db', 'private/monitor.db-wal', 'private/monitor.db-shm',
                     'private/master.key', 'private/service.log', '.hidden',
                     'backup-20261019-220000/monitor.db', 'backup-20261019-220000/master.key']:
            path = self.config/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic test data')
        self.external = self.root/'downloads/export.hmbackup'
        self.external.parent.mkdir()
        self.external.write_text('external backup')
        (self.config/'private/external-link').symlink_to(self.external.parent, target_is_directory=True)
        (self.config/'dangling-link').symlink_to(self.root/'missing')
        self.neighbor = self.config.parent/'OtherPackage'
        self.neighbor.mkdir()
        (self.neighbor/'keep').write_text('unrelated data')
        self.script = self.root/'postuninst'
        self.script.write_text(self.hook.replace('/var/packages/HardwareMonitor/etc', str(self.package/'etc'))
                               .replace('/volume[0-9]*', str(self.root)+'/volume[0-9]*')
                               .replace('${physical_dir#/volume}', '${physical_dir#'+str(self.root)+'/volume}')
                               .replace('/usr/syno/etc/packages/HardwareMonitor', str(self.root)+'/usr/syno/etc/packages/HardwareMonitor'))

    def run_hook(self, status='UNINSTALL', selected='true', package='HardwareMonitor'):
        env = {key: value for key, value in os.environ.items()
               if key not in {'SYNOPKG_PKG_STATUS', 'wizard_delete_data', 'SYNOPKG_PKGNAME'}}
        for key, value in [('SYNOPKG_PKG_STATUS', status), ('wizard_delete_data', selected), ('SYNOPKG_PKGNAME', package)]:
            if value is not None:
                env[key] = value
        return subprocess.run(['sh', str(self.script)], env=env, capture_output=True, text=True)

    def test_missing_false_or_unknown_choice_preserves_all_bytes(self):
        before = {str(p.relative_to(self.config)): p.read_bytes()
                  for p in self.config.rglob('*') if p.is_file() and not p.is_symlink()}
        for selected in [None, '', 'false', 'TRUE', '1', 'yes']:
            with self.subTest(selected=selected):
                result = self.run_hook(selected=selected)
                self.assertEqual(result.returncode, 0, result.stderr)
                after = {str(p.relative_to(self.config)): p.read_bytes()
                         for p in self.config.rglob('*') if p.is_file() and not p.is_symlink()}
                self.assertEqual(after, before)

    def test_updates_and_other_actions_never_delete_even_with_true_choice(self):
        for status in [None, '', 'UPGRADE', 'INSTALL', 'START', 'STOP', 'uninstall']:
            with self.subTest(status=status):
                result = self.run_hook(status=status)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.config/'private/monitor.db').exists())

    def test_opt_in_clears_state_backups_and_hidden_files_without_following_links(self):
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.config.iterdir()), [])
        self.assertTrue((self.package/'etc').is_symlink())
        self.assertEqual(self.external.read_text(), 'external backup')
        self.assertEqual((self.neighbor/'keep').read_text(), 'unrelated data')
        self.assertEqual(self.run_hook().returncode, 0)  # repeated cleanup is harmless

    def test_system_partition_configuration_path(self):
        destination = self.root/'usr/syno/etc/packages/HardwareMonitor'
        destination.parent.mkdir(parents=True)
        self.config.rename(destination)
        (self.package/'etc').unlink()
        (self.package/'etc').symlink_to(destination, target_is_directory=True)
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(destination.iterdir()), [])

    def test_wrong_package_and_unexpected_configuration_target_are_rejected(self):
        self.assertNotEqual(self.run_hook(package='OtherPackage').returncode, 0)
        self.assertTrue((self.config/'private/monitor.db').exists())
        (self.package/'etc').unlink()
        (self.package/'etc').symlink_to(self.external.parent, target_is_directory=True)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertTrue(self.external.exists())

    def test_absent_configuration_is_already_clean(self):
        (self.package/'etc').unlink()
        self.assertEqual(self.run_hook().returncode, 0)

    def test_cleanup_failure_is_reported(self):
        commands = self.root/'commands'
        commands.mkdir()
        fail = commands/'rm'
        fail.write_text('#!/bin/sh\nexit 1\n')
        fail.chmod(0o755)
        with mock.patch.dict(os.environ, {'PATH': str(commands)+os.pathsep+os.environ['PATH']}):
            self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertTrue((self.config/'private/monitor.db').exists())

    def wizard(self, name, version):
        metadata = self.root/'VERSION'
        metadata.write_text(f'productversion="{version}"\n')
        script = self.root/name
        script.write_text(self.wizards[name].replace('/etc.defaults/VERSION', str(metadata)))
        output = self.root/'wizard.json'
        result = subprocess.run(['sh', str(script)], env={**os.environ, 'SYNOPKG_TEMP_LOGFILE': str(output)},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(output.read_text())

    def test_localized_legacy_wizards_default_to_retention(self):
        self.assertEqual(set(self.wizards), {'uninstall_uifile.sh', 'uninstall_uifile_enu.sh', 'uninstall_uifile_ger.sh'})
        for version in ['7.0', '7.0.1', '7.1.1', '7.2', '7.2.1']:
            for name in self.wizards:
                with self.subTest(version=version, name=name):
                    step = self.wizard(name, version)[0]
                    checkbox = step['items'][0]['subitems'][0]
                    self.assertEqual(checkbox['key'], 'wizard_delete_data')
                    self.assertIs(checkbox['defaultValue'], False)
                    self.assertTrue(checkbox['desc'])
        self.assertEqual(self.wizard('uninstall_uifile.sh', '7.0'), self.wizard('uninstall_uifile_enu.sh', '7.0'))
        self.assertIn('löschen', self.wizard('uninstall_uifile_ger.sh', '7.0')[0]['items'][0]['subitems'][0]['desc'])

    def test_modern_wizard_exports_choice_and_resets_on_reopening(self):
        program = r'''
const vm = require('node:vm'), assert = require('node:assert/strict');
const step = JSON.parse(process.argv[1]);
let entry;
const getNext = () => 'next', checkState = () => {};
const useHook = () => ({ getNext, checkState }); useHook.props = {};
const context = { Vue: { ref: value => ({ value }) }, SYNO: { SDS: { PkgManApp: { Custom: {
  useHook, JsonpLoader: { load(module) { assert.equal(module.__esModule, true); entry = module.default; } }
} } } } };
vm.runInNewContext(step.custom_render_fn, context);
assert.equal(entry.name, step.custom_render_name);
const state = entry.render.setup({});
assert.equal(state.getNext, getNext); assert.equal(state.checkState, checkState);
assert.equal(state.getValues().wizard_delete_data, false);
const instance = new Proxy(state, {
  get(target, key) { return key === 'removeData' ? target[key].value : target[key]; },
  set(target, key, value) { target[key].value = value; return true; }
});
const tree = entry.render.render.call(instance, (name, options, children) =>
  ({ name, options: Array.isArray(options) ? {} : options, children: Array.isArray(options) ? options : children }));
assert.equal(tree.name, 'pkg-center-step-content');
const checkbox = tree.children[0].children[1].children[0];
assert.equal(checkbox.name, 'v-checkbox'); assert.equal(checkbox.options.model.value, false);
checkbox.options.model.callback(true); assert.equal(state.getValues().wizard_delete_data, true);
checkbox.options.model.callback(false); assert.equal(state.getValues().wizard_delete_data, false);
assert.equal(entry.render.setup({}).getValues().wizard_delete_data, false);
'''
        for version in ['7.2.2', '7.3', '7.4.1', '8.0']:
            for name in self.wizards:
                with self.subTest(version=version, name=name):
                    step = self.wizard(name, version)[0]
                    subprocess.run(['node', '-e', program, json.dumps(step)], check=True, capture_output=True)

    def test_invalid_version_fails_without_emitting_a_wizard(self):
        for version in ['', '7', '7.2.bad', '7..2', '7.2.2.1']:
            with self.subTest(version=version):
                metadata = self.root/'VERSION'
                metadata.write_text(f'productversion="{version}"\n')
                script = self.root/'wizard.sh'
                script.write_text(self.wizards['uninstall_uifile.sh'].replace('/etc.defaults/VERSION', str(metadata)))
                result = subprocess.run(['sh', str(script)], env={**os.environ, 'SYNOPKG_TEMP_LOGFILE': str(self.root/'invalid.json')},
                                        capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root/'invalid.json').exists())
