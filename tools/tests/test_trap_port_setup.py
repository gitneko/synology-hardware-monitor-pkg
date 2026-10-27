"""Execute the administrator helper with isolated command doubles, never root changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TrapPortSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = self.root/'commands'
        self.commands.mkdir()
        self.physical = self.root/'volume1/@appstore/HardwareMonitor'
        self.binary = self.physical/'bin/hardware-monitor'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text('synthetic executable, never executed')
        self.binary.chmod(0o755)
        package = self.root/'var/packages/HardwareMonitor'
        package.mkdir(parents=True)
        (package/'target').symlink_to(self.physical)
        self.trace = self.root/'trace'
        self.capability = self.root/'capability'
        self.env = {**os.environ, 'HM_TEST_TRACE': str(self.trace), 'HM_TEST_CAP': str(self.capability)}
        self.script = self.root/'setup.sh'
        package_file = os.environ.get('HARDWARE_MONITOR_TEST_SPK')
        if package_file:
            with tarfile.open(package_file) as archive:
                import io
                with tarfile.open(fileobj=io.BytesIO(archive.extractfile('package.tgz').read()), mode='r:gz') as payload:
                    source = payload.extractfile('scripts/setup-trap-port.sh').read().decode()
        else:
            source = (ROOT/'packaging/helpers/setup-trap-port.sh').read_text()
        self.script.write_text(source.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/syno/bin:/usr/syno/sbin', f'PATH={self.commands}:/usr/bin:/bin')
                              .replace('target=/var/packages/HardwareMonitor/target', f'target={package}/target')
                              .replace('/volume[0-9]*', str(self.root)+'/volume[0-9]*')
                              .replace('${physical#/volume}', '${physical#'+str(self.root)+'/volume}'))
        self.mock('id', 'echo "${HM_TEST_UID:-0}"')
        self.mock('chown', 'echo "chown $*" >> "$HM_TEST_TRACE"')
        self.mock('chmod', 'echo "chmod $*" >> "$HM_TEST_TRACE"')
        self.mock('synopkg', 'echo "synopkg $*" >> "$HM_TEST_TRACE"; test "${HM_TEST_STOP_FAIL:-0}" != 1 || test "$1" != stop')
        self.mock('getcap', 'test ! -f "$HM_TEST_CAP" || echo "$1 cap_net_bind_service=ep"')
        self.mock('setcap', '''
case "$1" in
    -v) test -f "$HM_TEST_CAP" ;;
    -r) echo "remove-cap $2" >> "$HM_TEST_TRACE"; rm -f "$HM_TEST_CAP" ;;
    cap_net_bind_service=ep)
        echo "set-cap $2" >> "$HM_TEST_TRACE"
        test "${HM_TEST_CAP_FAIL:-0}" != 1 || exit 1
        touch "$HM_TEST_CAP" ;;
    *) exit 2 ;;
esac''')

    def mock(self, name, body):
        path = self.commands/name
        path.write_text('#!/bin/sh\nset -eu\n'+body+'\n')
        path.chmod(0o755)

    def run_helper(self, *arguments, **env):
        return subprocess.run(['sh', str(self.script), *arguments], env={**self.env, **env}, capture_output=True, text=True, timeout=5)

    def test_enable_status_repeat_and_disable(self):
        self.assertNotEqual(self.run_helper('status').returncode, 0)
        self.assertFalse(self.trace.exists())
        for _ in range(2):
            result = self.run_helper('enable')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.run_helper('status').returncode, 0)
        lines = self.trace.read_text().splitlines()
        self.assertEqual(lines[:5], ['synopkg stop HardwareMonitor', f'chown root:HardwareMonitor {self.binary}', f'chmod 0750 {self.binary}', f'set-cap {self.binary}', 'synopkg start HardwareMonitor'])
        for _ in range(2):
            result = self.run_helper('disable')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.capability.exists())
        self.assertIn(f'chown HardwareMonitor:HardwareMonitor {self.binary}', self.trace.read_text())

    def test_unprivileged_caller_and_invalid_arguments_cannot_mutate(self):
        self.assertNotEqual(self.run_helper('enable', HM_TEST_UID='1234').returncode, 0)
        self.assertNotEqual(self.run_helper('unknown').returncode, 0)
        self.assertNotEqual(self.run_helper('enable', 'extra').returncode, 0)
        self.assertFalse(self.trace.exists())

    def test_failed_stop_or_capability_never_restart(self):
        self.assertNotEqual(self.run_helper('enable', HM_TEST_STOP_FAIL='1').returncode, 0)
        self.assertEqual(self.trace.read_text(), 'synopkg stop HardwareMonitor\n')
        self.trace.unlink()
        self.assertNotEqual(self.run_helper('enable', HM_TEST_CAP_FAIL='1').returncode, 0)
        self.assertNotIn('synopkg start', self.trace.read_text())

    def test_symlink_and_hardlink_executables_are_rejected(self):
        other = self.root/'other'
        self.binary.rename(other)
        self.binary.symlink_to(other)
        self.assertNotEqual(self.run_helper('enable').returncode, 0)
        self.binary.unlink()
        self.binary.hardlink_to(other)
        self.assertNotEqual(self.run_helper('enable').returncode, 0)
        self.assertFalse(self.trace.exists())

    def test_symlinked_binary_directory_is_rejected(self):
        elsewhere = self.root/'elsewhere'
        self.binary.parent.rename(elsewhere)
        self.binary.parent.symlink_to(elsewhere)
        self.assertNotEqual(self.run_helper('enable').returncode, 0)
        self.assertFalse(self.trace.exists())
