#!/usr/bin/env python3
"""Clone probe 0004 as 0005; only change INFO version and thirdparty flag."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
BASE = DIST / 'HardwareMonitorPrivilegeProbe-1.0.0-0004-v1000-dsm7.spk'
OUTPUT = DIST / 'HardwareMonitorPrivilegeProbe-1.0.0-0005-v1000-dsm7.spk'
BASE_SHA256 = 'f3619b704e6d451fd5f2a408db0b5f6f293ddb04dafff521c1c879ffe776d901'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def contents(path):
    with tarfile.open(path) as archive:
        return {member.name: archive.extractfile(member).read()
                for member in archive if member.isfile()}


if __name__ == '__main__':
    assert sha(BASE.read_bytes()) == BASE_SHA256, 'Unexpected baseline probe'
    assert not OUTPUT.exists(), 'Refusing to replace an existing probe'
    baseline = contents(BASE)
    info = baseline['INFO']
    assert info.count(b'version="1.0.0-0004"') == 1
    assert info.count(b'thirdparty="yes"') == 1
    changed = info.replace(b'version="1.0.0-0004"', b'version="1.0.0-0005"')
    changed = changed.replace(b'thirdparty="yes"', b'thirdparty="no"')
    assert b'maintainer="Hardware Monitor contributors"' in changed
    with tarfile.open(BASE) as original, tarfile.open(OUTPUT, 'w') as result:
        for member in original:
            entry = copy.copy(member)
            if member.isfile():
                body = changed if member.name == 'INFO' else original.extractfile(member).read()
                entry.size = len(body)
                result.addfile(entry, io.BytesIO(body))
            else:
                result.addfile(entry)
    generated = contents(OUTPUT)
    assert generated.keys() == baseline.keys()
    assert [name for name in baseline if baseline[name] != generated[name]] == ['INFO']
    assert generated['INFO'].replace(b'version="1.0.0-0005"', b'version="1.0.0-0004"').replace(
        b'thirdparty="no"', b'thirdparty="yes"') == info
    # Payload, resource, privilege, scripts and ownership/modes are unchanged.
    with tarfile.open(BASE) as a, tarfile.open(OUTPUT) as b:
        for old, new in zip(a.getmembers(), b.getmembers(), strict=True):
            for attribute in ['name', 'type', 'mode', 'uid', 'gid', 'uname', 'gname', 'linkname', 'mtime']:
                assert getattr(old, attribute) == getattr(new, attribute)
    digest = sha(OUTPUT.read_bytes())
    OUTPUT.with_suffix('.spk.sha256').write_text(digest + '  ' + OUTPUT.name + '\n')
    record = {
        'date': '2026-10-18', 'experiment': 'thirdparty=no metadata only',
        'baseline': BASE.name, 'baseline_sha256': BASE_SHA256,
        'output': OUTPUT.name, 'output_sha256': digest,
        'changed_INFO_fields': {'version': '1.0.0-0005', 'thirdparty': 'no'},
        'payload_sha256': sha(generated['package.tgz']),
        'all_other_members_and_metadata_unchanged': True,
        'maintainer': 'Hardware Monitor contributors',
        'vendor_signature_added': False, 'nas_result': 'pending',
        'local_checks': 'passed; exact content and archive metadata comparison to 0004',
        'documentation': 'Synology marks thirdparty unused since DSM 5.0; no documented resource authorization effect'
    }
    (DIST / 'privilege-probe-origin-metadata-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'{OUTPUT}\nSHA256 {digest}\nPASS: only version and thirdparty changed; NAS acceptance untested.')
