#!/usr/bin/env python3
"""Reconstruct the isolated candidate from its checksummed published crate."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAME = 'async-snmp-0.18.1'
SHA256 = '62c73521f81d79ffef8d7b3d4ece05c5d46f30729526a71af422aa0399cdc0b4'


def source_hash(directory):
    digest=hashlib.sha256()
    files=list((directory/'src').rglob('*.rs'))+[directory/'Cargo.toml']+list(directory.glob('LICENSE*'))
    for path in sorted(files):
        digest.update(str(path.relative_to(directory)).encode()+b'\x00')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def prepare():
    work = ROOT / '.build/snmp-reference'
    work.mkdir(parents=True, exist_ok=True)
    patch = HERE / 'patches' / f'{NAME}-routed-receiver.patch'
    destination = work / NAME
    stamp = work / 'prepared.sha256'
    patch_hash = hashlib.sha256(patch.read_bytes()).hexdigest()
    if destination.is_dir() and stamp.exists():
        try:
            recorded=json.loads(stamp.read_text())
            if recorded=={'patch':patch_hash,'source':source_hash(destination)}:
                return destination
        except (ValueError, OSError):
            pass
    archive = work / f'{NAME}.crate'
    if not archive.exists():
        cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
        cached = next((cargo_home / 'registry/cache').glob(f'*/{NAME}.crate'), None)
        if cached:
            shutil.copyfile(cached, archive)
        else:
            with urllib.request.urlopen(f'https://static.crates.io/crates/async-snmp/{NAME}.crate', timeout=30) as response:
                archive.write_bytes(response.read(8 * 1024 * 1024 + 1))
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError('candidate archive checksum mismatch')
    if destination.exists():
        shutil.rmtree(destination)
    with tarfile.open(archive) as source:
        # No paths, links or special files outside the one expected source tree.
        for member in source.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != NAME or '..' in parts or not (member.isdir() or member.isfile()):
                raise RuntimeError('unsafe crate archive member')
        source.extractall(work, filter='data')
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=destination, check=True)
    stamp.write_text(json.dumps({'patch':patch_hash,'source':source_hash(destination)})+'\n')
    return destination


def verify_vendor():
    """Verify the explicit patch chain against the checksummed published crate."""
    base = prepare()
    candidate = ROOT / '.build/snmp-reference/production-candidate'
    if candidate.exists():
        shutil.rmtree(candidate)
    shutil.copytree(base, candidate)
    manifest = json.loads((ROOT / 'vendor/async-snmp-provenance.json').read_text())
    for entry in manifest['additional_patches']:
        patch = ROOT / entry['path']
        if hashlib.sha256(patch.read_bytes()).hexdigest() != entry['sha256']:
            raise RuntimeError('additional patch checksum mismatch')
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=candidate, check=True)
    vendor = ROOT / 'vendor/async-snmp-0.18.1'
    actual = {str(p.relative_to(vendor)): hashlib.sha256(p.read_bytes()).hexdigest() for p in vendor.rglob('*') if p.is_file()}
    expected = {str(p.relative_to(candidate)): hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.rglob('*') if p.is_file()}
    omitted = manifest.get('omitted_files', {})
    if any(not name.startswith(('.github/', 'benches/', 'examples/')) for name in omitted):
        raise RuntimeError('production source cannot be omitted from vendor verification')
    if (set(actual) & set(omitted) or actual != manifest['files']
            or expected != {**actual, **omitted}):
        raise RuntimeError('vendored source differs from published crate plus checked patches')
    receiver_patch = ROOT / manifest['patch']
    if hashlib.sha256(receiver_patch.read_bytes()).hexdigest() != manifest['patch_sha256']:
        raise RuntimeError('receiver patch checksum mismatch')
    return vendor


if __name__ == '__main__':
    print(verify_vendor())
