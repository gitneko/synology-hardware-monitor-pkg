#!/usr/bin/env python3
"""Publish checked, fixed-name assets to the mutable development tag 'latest'."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote

NAMES = {'HardwareMonitor-dsm7-x86_64.spk',
         'SHA256SUMS', 'build-manifest.json'}
# Retired managed assets are cleaned up only after a successful replacement upload.
RETIRED_ASSETS = {'HardwareMonitor-dsm6-geminilake.spk'}
OLD_ASSET = r'HardwareMonitor-\d+\.\d+\.\d+-\d+-(?:v1000|geminilake|x86_64)-dsm[67]-development\.spk(?:\.sha256)?|build-manifest-\d+\.json'


def gh(*args, payload=None, missing=False):
    command = ['gh', *args]
    if payload is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        if missing and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError(f'GitHub command failed: {result.stderr.strip()}')
    return json.loads(result.stdout) if args[0] == 'api' and result.stdout.strip() else {}


def publish(directory, repository, commit, branch, client=gh):
    directory = Path(directory)
    if {p.name for p in directory.iterdir()} != NAMES:
        raise ValueError('Expected exactly the three checked DSM 7 release assets')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Expected a full source commit SHA')
    manifest = json.loads((directory/'build-manifest.json').read_text())
    if manifest.get('source_dirty'):
        raise ValueError('Dirty local build cannot be published as a source commit')
    if manifest['commit'] != commit:
        raise ValueError('Build/source commit mismatch')
    sums = {}
    for line in (directory/'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if name not in NAMES-{'SHA256SUMS'} or name in sums:
            raise ValueError('Invalid checksum filename')
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Release checksum mismatch')
        sums[name] = digest
    if set(sums) != NAMES-{'SHA256SUMS'}:
        raise ValueError('Incomplete checksums')
    if manifest['packages'] != {k: v for k, v in sums.items() if k.endswith('.spk')}:
        raise ValueError('Manifest/checksum mismatch')
    repo = f'repos/{repository}'
    current = client('api', f'{repo}/git/ref/heads/{quote(branch, safe="")}')
    if current['object']['sha'] != commit:
        print('Skipping superseded build: default branch has advanced.')
        return False
    release = client('api', f'{repo}/releases/tags/latest', missing=True)
    if release and release.get('immutable'):
        raise ValueError('The latest release is immutable; rolling assets require mutable releases')
    tag = client('api', f'{repo}/git/ref/tags/latest', missing=True)
    if tag:
        client('api', '--method', 'PATCH', f'{repo}/git/refs/tags/latest', payload={'sha': commit, 'force': True})
    else:
        client('api', '--method', 'POST', f'{repo}/git/refs', payload={'ref': 'refs/tags/latest', 'sha': commit})
    notes = (f"Rolling development build **{manifest['version']}** from `{commit}`.\n\n"
             'Unsigned DSM 7 x86_64 SPK for v1000, geminilake and other compatible x86_64 platforms.\n\n'
             'Verify downloads against SHA256SUMS. This mutable tag and its fixed-name assets '
             'are replaced after successful default-branch builds. Replacement is not atomic.')
    with tempfile.TemporaryDirectory() as temp:
        notes_file = Path(temp)/'notes.md'
        notes_file.write_text(notes)
        paths = [str(directory/name) for name in sorted(NAMES)]
        if release:
            client('release', 'upload', 'latest', *paths, '--clobber', '--repo', repository)
            client('release', 'edit', 'latest', '--title', 'Latest development build',
                   '--notes-file', str(notes_file), '--prerelease', '--repo', repository)
            for asset in release['assets']:
                name = asset['name']
                if name not in NAMES and (name in RETIRED_ASSETS or re.fullmatch(OLD_ASSET, name)):
                    client('release', 'delete-asset', 'latest', name, '--yes', '--repo', repository)
        else:
            client('release', 'create', 'latest', *paths, '--verify-tag', '--prerelease',
                   '--title', 'Latest development build', '--notes-file', str(notes_file), '--repo', repository)
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    publish(args.directory, os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'],
            os.environ['DEFAULT_BRANCH'])
