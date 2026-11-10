#!/usr/bin/env python3
"""Stage and replace the complete application without touching server state."""
import ast
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

DIRECTORIES = ('access_gate', 'templates', 'static')
FILES = ('wsgi.py', 'configure.py', 'VERSION')


def deploy(source, destination):
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if destination.is_symlink():
        raise ValueError('The application destination must not be a symlink.')
    if source == destination.resolve() or source in destination.resolve().parents or destination.resolve() in source.parents:
        raise ValueError('Keep the source checkout and installed application in separate directories.')
    for name in DIRECTORIES + FILES:
        item = source/name
        if not item.exists() or item.is_symlink():
            raise ValueError(f'Missing or unsupported source item: {name}')
    for name in DIRECTORIES:
        if not (source/name).is_dir():
            raise ValueError(f'Expected a source directory: {name}')
        if any(p.is_symlink() for p in (source/name).rglob('*')):
            raise ValueError(f'Source symlinks are not supported: {name}')
    for name in FILES:
        if not (source/name).is_file():
            raise ValueError(f'Expected a source file: {name}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.access-gate-stage-',dir=destination.parent))
    previous = None
    try:
        for name in DIRECTORIES:
            shutil.copytree(source/name,stage/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.pyo'))
        for name in FILES:
            shutil.copy2(source/name,stage/name)
        for p in stage.rglob('*.py'):
            ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
        # Give the unprivileged portal user read access; installed code stays root-owned.
        stage.chmod(0o755)
        for p in stage.rglob('*'):
            p.chmod(0o755 if p.is_dir() else 0o644)
        if destination.exists():
            previous = destination.parent/('.access-gate-previous-'+uuid.uuid4().hex)
            os.replace(destination,previous)
        try:
            os.replace(stage,destination)
        except BaseException:
            if previous is not None:
                os.replace(previous,destination)
                previous = None
            raise
        return previous
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: deploy_portal.py SOURCE DESTINATION')
    backup = deploy(sys.argv[1],sys.argv[2])
    print('Complete portal deployed.' + (f' Previous code: {backup}' if backup else ''))
