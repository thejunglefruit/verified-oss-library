# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Starts a long library job IN THE BACKGROUND, detached from the terminal.

Why: fetching a large catalog takes an hour or more (clones, Defender scans). Run inside an agent session
or a terminal that gets closed, the session sits waiting or dies with it. This launcher starts an
independent process that writes to <library>/_logs/<date>_<task>.log and gives control back at once.
Check progress with:  python status.py

Usage:
  python launch.py fetch [fetch.py args]     e.g. python launch.py fetch --only gimp,olive
  python launch.py analyze                   analyzer.py over the clones
  python launch.py readmes                   readmes.py
  python launch.py chain [fetch.py args]     fetch -> analyze -> readmes -> report
  python launch.py post                      analyze -> readmes -> report (no download)
  python launch.py update                    fetch --update -> analyze -> readmes -> report
  --after 1234,5678   (any task) waits for those PIDs to exit before starting, so a job can be queued
                      behind one that is already running without polling from the session.
"""
import os
import subprocess
import sys
import time

import settings

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
REPORT = ['fetch.py', '--report']

STEPS = {
    'fetch': [['fetch.py']],
    'analyze': [['analyzer.py']],
    'readmes': [['readmes.py']],
    'chain': [['fetch.py'], ['analyzer.py'], ['readmes.py'], REPORT],
    'post': [['analyzer.py'], ['readmes.py'], REPORT],
    'update': [['fetch.py', '--update'], ['analyzer.py'], ['readmes.py'], REPORT],
}
TAKES_EXTRA = ('fetch.py',)   # user arguments are passed to these scripts only (never to the report step)


def commands(task, extra):
    """The command lines a task will run, in order."""
    out = []
    for step in STEPS[task]:
        args = list(extra) if step[0] in TAKES_EXTRA and '--report' not in step else []
        out.append([PY, '-u', os.path.join(HERE, step[0])] + step[1:] + args)
    return out


def pid_alive(pid):
    if sys.platform == 'win32':
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, int(pid))  # SYNCHRONIZE
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def wait_for(pids):
    """Blocks (in the detached process, never in the session) until every PID has exited."""
    for pid in pids:
        if not pid_alive(pid):
            print(f'pid {pid}: already gone', flush=True)
            continue
        print(f"{time.strftime('%H:%M:%S')} waiting for pid {pid}...", flush=True)
        if sys.platform == 'win32':
            import ctypes
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x00100000, False, int(pid))
            if h:
                k.WaitForSingleObject(h, 0xFFFFFFFF)
                k.CloseHandle(h)
        else:
            while pid_alive(pid):
                time.sleep(10)
        print(f"{time.strftime('%H:%M:%S')} pid {pid} finished", flush=True)


def split_after(extra):
    extra = list(extra)
    if '--after' not in extra:
        return extra, []
    i = extra.index('--after')
    if i + 1 >= len(extra):
        raise SystemExit('--after needs a list of PIDs: --after 1234,5678')
    pids = extra[i + 1].split(',')
    del extra[i:i + 2]
    return extra, pids


def execute(task, extra):
    """Runs the steps one after another (this is what lives in the detached process)."""
    extra, pids = split_after(extra)
    wait_for(pids)
    for cmd in commands(task, extra):
        print(f"\n===== {time.strftime('%H:%M:%S')} {' '.join(os.path.basename(c) for c in cmd[2:])}", flush=True)
        # explicit redirection: without it the grandchild does not inherit the handle on Windows
        r = subprocess.run(cmd, cwd=HERE, stdout=sys.stdout, stderr=subprocess.STDOUT)
        print(f"===== end ({r.returncode}) {time.strftime('%H:%M:%S')}", flush=True)
    print('===== TASK COMPLETE', flush=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 2 and argv[0] == '--_execute':
        execute(argv[1], argv[2:])
        return 0
    if not argv or argv[0] not in STEPS:
        print(__doc__)
        return 1
    task, extra = argv[0], argv[1:]
    split_after(extra)  # validate before detaching
    logs = settings.logs_dir()
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f"{time.strftime('%Y%m%d_%H%M')}_{task}.log"
    kw = dict(cwd=HERE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, close_fds=True)
    flags = 0
    if sys.platform == 'win32':
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
    else:
        kw['start_new_session'] = True
    cmd = [PY, '-u', os.path.join(HERE, 'launch.py'), '--_execute', task] + extra
    with open(log, 'w', encoding='utf-8') as out:
        out.write(f"# {task} {' '.join(extra)}  started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.flush()
        try:
            p = subprocess.Popen(cmd, stdout=out, creationflags=flags, **kw)
        except OSError:
            # CREATE_BREAKAWAY_FROM_JOB fails when the parent job does not allow it
            p = subprocess.Popen(cmd, stdout=out, creationflags=flags & ~getattr(subprocess, 'CREATE_BREAKAWAY_FROM_JOB', 0), **kw)
    (logs / 'last.pid').write_text(str(p.pid), 'utf-8')
    print(f'started pid {p.pid}  log: {log}')
    print('progress: python status.py')
    return 0


if __name__ == '__main__':
    sys.exit(main())
