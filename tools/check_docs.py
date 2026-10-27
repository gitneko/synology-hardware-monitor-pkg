#!/usr/bin/env python3
"""Check local Markdown links/heading anchors in maintained source or SPK docs.

External URLs are not fetched. Paths are POSIX archive/repository paths; code
fences and inline code are excluded. The same checker accepts SPK member bytes
without extracting or executing their contents.
"""
import argparse
from collections import Counter
import html
from pathlib import Path
import posixpath
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def prose(source):
    lines = []
    fence = None
    for line in source.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            marker = match[1]
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return '\n'.join(lines)


def heading_ids(source):
    seen = Counter()
    ids = set()
    for title in re.findall(r'^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$', prose(source), re.M):
        title = html.unescape(re.sub(r'<[^>]*>', '', title)).lower()
        title = re.sub(r'[^\w\- ]', '', title).replace(' ', '-')
        ids.add(title if not seen[title] else f'{title}-{seen[title]}')
        seen[title] += 1
    return ids


def check_links(files):
    """Return broken links for a mapping of relative member paths to bytes."""
    errors = []
    for name, data in sorted(files.items()):
        if not name.endswith('.md'):
            continue
        source = re.sub(r'`+[^`\n]*`+', '', prose(data.decode('utf-8')))
        for raw in re.findall(r'!?\[[^\]\n]*\]\(([^\n]+?)\)', source):
            target = raw[1:raw.index('>')] if raw.startswith('<') else raw.split()[0]
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            path = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(url.path))) if url.path else name
            if path.startswith(('/', '../')) or path not in files:
                errors.append(f'{name}: missing local target {target}')
            elif url.fragment and path.endswith('.md') and unquote(url.fragment) not in heading_ids(files[path].decode('utf-8')):
                errors.append(f'{name}: missing heading {target}')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    documents = [ROOT/'README.md', *(ROOT/'docs').rglob('*'), *(ROOT/'tools').rglob('README.md')]
    files = {p.relative_to(ROOT).as_posix(): p.read_bytes() for p in documents
             if p.is_file() and 'history' not in p.relative_to(ROOT).parts}
    errors = check_links(files)
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'PASS maintained documentation: {sum(name.endswith(".md") for name in files)} Markdown files, local links and heading anchors')


if __name__ == '__main__':
    main()
