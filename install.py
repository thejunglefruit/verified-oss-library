# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
r"""Installs programs from the verified library into <apps_dir>\<id> without dialogs (Windows).

Install kinds (detected automatically):
  zip / 7z            -> extracted into <apps_dir>\<id> (portable)
  NSIS exe            -> /S /D=<apps_dir>\<id>
  Inno Setup exe      -> /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=<apps_dir>\<id>
  Squirrel/other exe  -> tries /S; if it does not take it, the entry says "install by hand"
  msi                 -> msiexec /i /qn (the package's default location)
Nothing is installed unless its verification.json says Defender found nothing and the SHA256 matched
(or the source publishes no checksum).

Usage:
  python install.py --category 05,06,13     # categories (numeric prefix)
  python install.py --only kdenlive,shotcut
  python install.py --list                  # what is installed (<apps_dir>\INSTALLED.md)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import settings


def installer_kind(p):
    """Looks at the strings inside the installer to tell which engine built it."""
    with open(p, 'rb') as f:
        head = f.read(4_000_000)
    if b'Inno Setup' in head:
        return 'inno'
    if b'Nullsoft' in head or b'NSIS' in head:
        return 'nsis'
    if b'Squirrel' in head:
        return 'squirrel'
    return 'unknown'


def executables(dest):
    found = [p for p in dest.rglob('*.exe') if 'unins' not in p.name.lower() and 'vc_redist' not in p.name.lower()]
    found.sort(key=lambda p: (len(p.parts), p.name))
    return [p.relative_to(dest).as_posix() for p in found[:6]]


def in_program_files(e):
    """Finds the program in Program Files when the installer ignores /D (some NSIS builds do)."""
    names = {e['id'].lower(), e['name'].lower(), e['name'].lower().replace(' ', '')}
    bases = [os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'),
             os.path.join(os.environ['LOCALAPPDATA'], 'Programs') if os.environ.get('LOCALAPPDATA') else None]
    for base in filter(None, bases):
        base = Path(base)
        if not base.exists():
            continue
        for d in base.iterdir():
            if d.is_dir() and d.name.lower() in names and any(d.rglob('*.exe')):
                return d
    return None


def blocked(v):
    """Why a verified download must not be installed, or None."""
    if not v or not v.get('file'):
        return 'no installer (source clone or not downloaded yet)'
    if str(v.get('defender', '')).startswith('THREAT') or v.get('sha256_ok') is False:
        return 'BLOCKED: failed verification'
    if str(v.get('verdict', '')).startswith('NOT KEPT'):
        return 'BLOCKED: quarantined'
    return None


def flatten(dest):
    """An archive with a single top folder: move its content one level up."""
    children = list(dest.iterdir())
    if len(children) == 1 and children[0].is_dir():
        inner = children[0]
        for c in inner.iterdir():
            shutil.move(str(c), str(dest / c.name))
        inner.rmdir()


def extract(archive, dest):
    """7-Zip when available; the standard library for plain .zip files otherwise. Returns an error text or None."""
    sz = settings.sevenzip()
    if sz.exists():
        p = subprocess.run([str(sz), 'x', '-y', f'-o{dest}', str(archive)], capture_output=True, text=True, timeout=1800)
        return ('ERROR extracting: ' + p.stderr[-200:]) if p.returncode else None
    if archive.suffix.lower() == '.zip':
        with zipfile.ZipFile(archive) as z:
            for m in z.namelist():  # refuse entries that would escape the target folder
                if not (dest / m).resolve().is_relative_to(dest.resolve()):
                    return f'ERROR: unsafe path in archive: {m}'
            z.extractall(dest)
        return None
    return '7-Zip not found: set OSS_7Z or "sevenzip" in config.json'


def install(e, root=None, apps=None):
    root = root or settings.library_root()
    apps = apps or settings.apps_dir()
    folder = root / e['category'] / e['id']
    vf = folder / 'verification.json'
    v = json.loads(vf.read_text('utf-8')) if vf.exists() else None
    why = blocked(v)
    if why:
        return dict(id=e['id'], status=why)
    archive = folder / v['file']
    if not archive.exists():
        return dict(id=e['id'], status='downloaded file is missing')
    dest = apps / e['id']
    r = dict(id=e['id'], name=e['name'], file=v['file'], version=v.get('version'), dest=str(dest), date=time.strftime('%Y-%m-%d %H:%M'))
    ext = archive.suffix.lower()
    if ext in ('.zip', '.7z'):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        err = extract(archive, dest)
        if err:
            r['status'] = err
            return r
        flatten(dest)
        r['status'] = 'portable extracted'
        r['kind'] = 'portable'
    elif ext == '.msi':
        p = subprocess.run(['msiexec', '/i', str(archive), '/qn', '/norestart'], capture_output=True, text=True, timeout=1800)
        r['status'] = 'installed (msi)' if p.returncode in (0, 3010) else f'ERROR msiexec {p.returncode}'
        r['kind'] = 'msi'
    elif ext == '.exe':
        kind = installer_kind(archive)
        r['kind'] = kind
        dest.mkdir(parents=True, exist_ok=True)
        if kind == 'inno':
            args = [str(archive), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOCANCEL', f'/DIR={dest}']
        elif kind == 'nsis':
            args = [str(archive), '/S', f'/D={dest}']  # /D must be last and unquoted
        else:
            args = [str(archive), '/S']
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=1800)
            ok = p.returncode == 0 and any(dest.rglob('*.exe'))
            if p.returncode == 0 and not ok:
                other = in_program_files(e)
                if other:
                    if dest.exists() and not any(dest.iterdir()):
                        dest.rmdir()
                    dest = other
                    r['dest'] = str(dest)
                    ok = True
                    r['status'] = f'installed ({kind}) in {dest} (the installer ignores /D)'
            if 'status' not in r:
                r['status'] = f'installed ({kind})' if ok else f'{kind} installer returned {p.returncode}; ' + (
                    'installed elsewhere or by hand' if p.returncode == 0 else 'install by hand')
        except subprocess.TimeoutExpired:
            r['status'] = 'TIMEOUT: the installer asked for input; install by hand'
        except OSError as ex:
            if getattr(ex, 'winerror', None) == 740:   # the installer demands UAC elevation
                r['status'] = f'needs elevation: run from an administrator terminal  python install.py --only {e["id"]}'
            else:
                raise
    else:
        r['status'] = f'{ext} files are not automated'
    if dest.exists():
        r['executables'] = executables(dest)
    return r


def register(results, apps=None):
    apps = apps or settings.apps_dir()
    apps.mkdir(parents=True, exist_ok=True)
    f = apps / 'installed.json'
    everything = json.loads(f.read_text('utf-8')) if f.exists() else {}
    for r in results:
        everything[r['id']] = r
    f.write_text(json.dumps(everything, ensure_ascii=False, indent=1), 'utf-8')
    lines = ['# Installed programs', '', f'Updated {time.strftime("%Y-%m-%d %H:%M")} by `install.py`.', '',
             '| Program | Version | Status | Executable | Folder |', '|---|---|---|---|---|']
    for r in sorted(everything.values(), key=lambda x: x['id']):
        exe = (r.get('executables') or [''])[0]
        lines.append(f"| {r.get('name', r['id'])} | {r.get('version') or ''} | {r.get('status', '')} | `{exe}` | `{r.get('dest', '')}` |")
    (apps / 'INSTALLED.md').write_text('\n'.join(lines) + '\n', 'utf-8')


def main(argv=None):
    ap = argparse.ArgumentParser(description='Install verified downloads silently.')
    ap.add_argument('--category', help='comma-separated category prefixes')
    ap.add_argument('--only', help='comma-separated ids')
    ap.add_argument('--list', action='store_true', help='print INSTALLED.md')
    a = ap.parse_args(argv)
    apps = settings.apps_dir()
    if a.list:
        f = apps / 'INSTALLED.md'
        print(f.read_text('utf-8') if f.exists() else 'nothing installed')
        return
    only = set(a.only.split(',')) if a.only else None
    cats = tuple(c.strip() for c in a.category.split(',')) if a.category else None
    results = []
    for e in settings.load_catalog():
        if (only and e['id'] not in only) or (cats and not e['category'].startswith(cats)) or e['source']['type'] == 'clone':
            continue
        t0 = time.time()
        try:
            r = install(e)
        except Exception as ex:  # noqa: BLE001 - report and keep going
            r = dict(id=e['id'], status=f'EXCEPTION: {ex}')
        r['seconds'] = round(time.time() - t0)
        results.append(r)
        print(f"{r['id']:22s} {r.get('status', '')}  {(r.get('executables') or [''])[0]}  {r['seconds']}s", flush=True)
    register(results)


if __name__ == '__main__':
    sys.exit(main())
