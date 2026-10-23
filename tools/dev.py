#!/usr/bin/env python3
"""Build and start the complete local app without DSM or an SPK."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18774)
    parser.add_argument('--directory', type=Path, default=ROOT/'local-state')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not (ROOT/'web/node_modules/vite').is_dir():
        subprocess.run(['npm', 'ci', '--prefix', 'web', '--ignore-scripts'], cwd=ROOT, check=True)
    subprocess.run(['npm', 'run', 'build', '--prefix', 'web'], cwd=ROOT, check=True)
    os.chdir(ROOT)
    os.execvp('cargo', ['cargo', 'run', '--locked', '--features', 'local-dev', '--', 'dev',
                       '--directory', str(directory), '--port', str(args.port),
                       '--web-root', str(ROOT/'web/dist')])


if __name__ == '__main__':
    main()
