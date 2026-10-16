# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Instant summary of the library, without blocking anything.

Reads the catalog, the logs (<library>/_logs/*.log) and the verification.json files and says how many
programs are done, which failed and why, which are still missing, whether a fetch/analyzer job is running
right now, and the last lines of the newest log. It is what you run while launch.py works in the background.

Usage:  python status.py            summary
        python status.py --failed   only the failures with their reason
        python status.py --missing  only the pending ids (comma-separated, ready for --only)
"""
import re
import subprocess
import sys
import time

import settings

LINE = re.compile(r'^(OK|FAIL)\s+([^/\s]+)/([^\s:]+):?\s*(.*)')
TOOLS = ('fetch', 'analyzer', 'readmes', 'launch', 'install')


def parse_logs(logs):
    """id -> (OK|FAIL, text, log name); later logs win."""
    state = {}
    for lg in logs:
        for line in lg.read_text('utf-8', errors='replace').splitlines():
            m = LINE.match(line)
            if m:
                state[m.group(3)] = (m.group(1), m.group(4).strip(), lg.name)
    return state


def processes():
    """Python processes of this tool that are still alive."""
    pattern = '|'.join(TOOLS)
    try:
        if sys.platform == 'win32':
            cmd = ("Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
                   f"Where-Object {{ $_.CommandLine -match '({pattern})\\.py' }} | "
                   "ForEach-Object { '{0}|{1}|{2}' -f $_.ProcessId, $_.CreationDate.ToString('HH:mm'), $_.CommandLine }")
            out = subprocess.run(['powershell', '-NoProfile', '-Command', cmd], capture_output=True, text=True, timeout=30).stdout
        else:
            out = subprocess.run(['ps', '-eo', 'pid,lstart,args'], capture_output=True, text=True, timeout=30).stdout
            out = '\n'.join(line for line in out.splitlines() if re.search(rf'python.*({pattern})\.py', line))
        return [line.strip() for line in out.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError) as ex:
        return [f'? {ex}']


def summarise(catalog, root, logs):
    ids = {e['id']: e for e in catalog}
    state = parse_logs(logs)
    done = {v.parent.name for v in root.glob('*/*/verification.json') if v.parent.parent.name != '_quarantine'}
    failed = [(i, state[i][1]) for i in ids if state.get(i, ('',))[0] == 'FAIL' and i not in done]
    failed_ids = {i for i, _ in failed}
    missing = [i for i in ids if i not in done and i not in failed_ids]
    return dict(ids=ids, done=[i for i in ids if i in done], failed=failed, missing=missing)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    root = settings.library_root()
    logs = sorted(settings.logs_dir().glob('*.log')) if settings.logs_dir().exists() else []
    s = summarise(settings.load_catalog(), root, logs)
    ids = s['ids']
    if '--failed' in argv:
        for i, t in s['failed']:
            print(f'{ids[i]["category"]}/{i}: {t}')
        return
    if '--missing' in argv:
        print(','.join(s['missing']))
        return
    print(f"catalog: {len(ids)}  done: {len(s['done'])}  failed: {len(s['failed'])}  pending: {len(s['missing'])}")
    procs = processes()
    print('running jobs:', 'none' if not procs else '')
    for p in procs:
        print('  ', p[:160])
    if logs:
        last = max(logs, key=lambda p: p.stat().st_mtime)
        age = (time.time() - last.stat().st_mtime) / 60
        print(f'latest log: {last.name}  (written {age:.0f} min ago)')
        for line in last.read_text('utf-8-sig', errors='replace').splitlines()[-4:]:
            print('  ', line[:150])
    if s['failed']:
        print('\nFAILED:')
        for i, t in s['failed']:
            print(f'  {ids[i]["category"]}/{i}: {t[:120]}')
    if s['missing']:
        by_cat = {}
        for i in s['missing']:
            by_cat.setdefault(ids[i]['category'], []).append(i)
        print('\nPENDING by category:')
        for c, items in sorted(by_cat.items()):
            print(f'  {c}: {len(items)}  ({", ".join(items[:6])}{"…" if len(items) > 6 else ""})')
    no_analysis = [v.parent.name for v in root.glob('*/*/code') if not (v.parent / 'ANALYSIS.md').exists() and v.parent.parent.name != '_quarantine']
    if no_analysis:
        print(f'\nclones without ANALYSIS.md: {len(no_analysis)}  -> python launch.py analyze')
    no_readme = [v.parent.name for v in root.glob('*/*/verification.json') if not (v.parent / 'README.md').exists() and v.parent.parent.name != '_quarantine']
    if no_readme:
        print(f'programs without README.md: {len(no_readme)}  -> python launch.py readmes')


if __name__ == '__main__':
    main()
