#!/usr/bin/env python3
"""Collect dependency-provided license texts for binary redistribution review."""
import argparse,json,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--musl-copyright',type=Path,required=True);a=p.parse_args()
metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--offline','--format-version','1','--filter-platform','x86_64-unknown-linux-musl','--manifest-path',str(root/'Cargo.toml')]))
sections=['THIRD PARTY NOTICES\n\nCollected dependency-provided license texts; includes build/development dependencies where present.\nExact versions are recorded in Cargo.lock and web/package-lock.json. This file is not a legal audit.\n']
for package in sorted(metadata['packages'],key=lambda x:(x['name'],x['version'])):
    if package['name']=='hardware-monitor':continue
    base=Path(package['manifest_path']).parent
    files=[f for f in base.rglob('*') if f.is_file() and len(f.relative_to(base).parts)<=2 and f.name.lower().startswith(('license','licence','copying','notice'))]
    sections.append(f"\n{'='*72}\n{package['name']} {package['version']}\nDeclared license: {package.get('license')}\nRepository: {package.get('repository')}\n")
    for f in sorted(files):sections.append(f'\n--- {f.relative_to(base)} ---\n'+f.read_text(errors='replace'))
# Production Vue bundle contains these modules; build tools are not shipped in SPKs.
for name in ['vue','@vue/shared','@vue/reactivity','@vue/runtime-core','@vue/runtime-dom']:
    base=root/'web/node_modules'/name
    if base.exists():
        package=json.loads((base/'package.json').read_text())
        sections.append(f"\n{'='*72}\n{name} {package['version']}\nDeclared license: {package.get('license')}\n")
        for f in base.iterdir():
            if f.is_file() and f.name.lower().startswith(('license','notice')):sections.append(f.read_text(errors='replace'))
sections.append('\n'+'='*72+'\nmusl 1.2.5\n'+a.musl_copyright.read_text())
(root/'THIRD_PARTY_NOTICES.txt').write_text('\n'.join(sections))
print(f'Collected notices for {len(metadata["packages"])-1} Rust packages, Vue runtime, and musl')
