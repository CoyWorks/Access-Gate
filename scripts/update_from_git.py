#!/usr/bin/env python3
"""Fast-forward a clean checkout, then run the newly downloaded updater."""
import os
from pathlib import Path
import subprocess
import sys


class UpdateError(RuntimeError):
    pass


def git(repo, *args, check=True):
    try:
        result = subprocess.run(['git','-C',str(repo),*args],text=True,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise UpdateError('Git is required. Install git before updating.') from exc
    if check and result.returncode:
        raise UpdateError(result.stderr.strip() or result.stdout.strip() or 'Git command failed.')
    return result


def synchronize(repo):
    repo = Path(repo).resolve()
    top = git(repo,'rev-parse','--show-toplevel',check=False)
    if top.returncode or Path(top.stdout.strip()).resolve() != repo:
        raise UpdateError('Run this updater from a complete Git clone. For extracted archives use update.sh --local or the download launcher.')
    if git(repo,'symbolic-ref','--quiet','--short','HEAD',check=False).stdout.strip() != 'main':
        raise UpdateError('Switch to the main branch before updating.')
    if git(repo,'status','--porcelain','--untracked-files=all').stdout.strip():
        raise UpdateError('Local changes or untracked files found. Commit or move them before updating; nothing was overwritten.')
    previous = git(repo,'rev-parse','HEAD').stdout.strip()
    print('Fetching the latest origin/main...',flush=True)
    git(repo,'fetch','--prune','origin','+refs/heads/main:refs/remotes/origin/main')
    if git(repo,'rev-parse','HEAD').stdout.strip() != previous or git(repo,'status','--porcelain','--untracked-files=all').stdout.strip():
        raise UpdateError('The checkout changed during the fetch. Installation was not started.')
    latest = git(repo,'rev-parse','refs/remotes/origin/main').stdout.strip()
    if git(repo,'merge-base','--is-ancestor',previous,latest,check=False).returncode:
        raise UpdateError('Local and remote history diverged, or local commits are unpublished. Installation was not started.')
    git(repo,'merge','--ff-only','--no-edit','refs/remotes/origin/main')
    print('Using commit '+latest[:12],flush=True)
    return latest


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: update_from_git.py SOURCE_DIRECTORY')
    repo = Path(sys.argv[1]).resolve()
    try:
        synchronize(repo)
    except UpdateError as exc:
        print('Update stopped: '+str(exc),file=sys.stderr)
        return 1
    # Run the NEW updater, not the script version that initiated the fetch.
    # --local prevents another fetch and therefore avoids recursion.
    os.execv('/bin/bash',['bash',str(repo/'update.sh'),'--local'])


if __name__=='__main__':
    raise SystemExit(main())
