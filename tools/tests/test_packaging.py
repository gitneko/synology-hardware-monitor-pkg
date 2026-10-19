"""Packaging scope checks; no NAS or compiler is needed."""
from pathlib import Path
import subprocess
import sys
import unittest


class PackagingScopeTests(unittest.TestCase):
    def test_retired_dsm6_profile_is_rejected_before_accessing_build_inputs(self):
        result = subprocess.run([
            sys.executable, str(Path(__file__).parents[1]/'build_spk.py'),
            '--profile', 'dsm6', '--binary', 'unused-input',
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid choice', result.stderr)
        self.assertIn('dsm6', result.stderr)
