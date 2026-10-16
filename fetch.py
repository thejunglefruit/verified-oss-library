# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Verified downloader for open-source programs and plugins.

Reads the catalog and, for each entry, resolves its official source:
  gh     -> latest official GitHub release (asset by regex, optional tag regex); SHA256 from GitHub's `digest` field
  winget -> installer URL and SHA256 from the winget manifest (Microsoft's reviewed repository)
  url    -> direct download from the official website (SHA256 only if the catalog gives one; otherwise flagged)
  clone  -> git clone --depth 1 of the source code (plugins, scripts, Python/web projects)
Then: checks the SHA256, scans with Microsoft Defender and, for clones, runs scanner.py (static analysis
of malware patterns). Everything lands in <library>/<category>/<id>/verification.json and in REPORT.md.

Usage:
  python fetch.py                    # everything that is missing
  python fetch.py --only shotcut,gimp
  python fetch.py --category 01_video
  python fetch.py --update           # ask for the latest version again even if one is already there
  python fetch.py --report           # only rebuild REPORT.md
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import scanner
import settings

UA = {'User-Agent': 'Mozilla/5.0 (verified-oss-library)'}
KEEP = ('verification.json', 'README.md', 'SCAN.md', 'ANALYSIS.md', 'analysis.json')


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', **kw)


# ---------------------------------------------------------------- resolvers

def gh_json(path):
    p = run(['gh', 'api', path])
    if p.returncode:
        raise RuntimeError(p.stderr.strip()[:200])
    return json.loads(p.stdout)


def resolve_gh(src):
    releases = gh_json(f"repos/{src['repo']}/releases?per_page=40")
    tag = re.compile(src.get('tag', '.*'))
    asset = re.compile(src['asset'], re.I)
    for r in releases:
        if r['draft'] or (r['prerelease'] and not src.get('prerelease')):
            continue
        if not tag.search(r['tag_name']):
            continue
        for a in r['assets']:
            if asset.search(a['name']):
                sha = (a.get('digest') or '').removeprefix('sha256:') or None
                return dict(url=a['browser_download_url'], name=a['name'], version=r['tag_name'], sha256=sha, size=a['size'])
    raise RuntimeError('no release has an asset matching ' + src['asset'])


# winget prints its labels in the system language: English and Spanish are recognised
WINGET_URL = re.compile(r'(?:Installer Url|URL del instalador):\s*(\S+)')
WINGET_SHA = re.compile(r'(?:Installer SHA256|Instalador SHA256):\s*([0-9a-fA-F]{64})')
WINGET_VER = re.compile(r'^(?:Version|Versi.n):\s*(\S+)', re.M)


def resolve_winget(src):
    t = run(['winget', 'show', '--id', src['id'], '-e', '--accept-source-agreements']).stdout
    url, sha, ver = WINGET_URL.search(t), WINGET_SHA.search(t), WINGET_VER.search(t)
    if not url:
        raise RuntimeError('winget has no manifest for ' + src['id'])
    u = url.group(1)
    parts = [s for s in u.split('?')[0].split('/') if s]
    name = parts[-2] if parts[-1] == 'download' else parts[-1]  # sourceforge: .../file.exe/download
    return dict(url=u, name=src.get('name') or name, version=ver.group(1) if ver else '?',
                sha256=sha.group(1).lower() if sha else None, size=None)


def resolve_url(src):
    return dict(url=src['url'], name=src.get('name') or src['url'].split('/')[-1], version=src.get('version', '?'),
                sha256=src.get('sha256'), size=None)


RESOLVERS = {'gh': resolve_gh, 'winget': resolve_winget, 'url': resolve_url}


# ---------------------------------------------------------------- download and checks

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def download(url, dest):
    """urllib first; if it fails (TLS intercepted by an antivirus, timeout) retry with curl, which uses the
    system certificate store. Plain http is refused. Returns the SHA256 of the file."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ('https', 'file'):
        raise RuntimeError(f'refusing to download over {scheme or "an unknown scheme"}: {url}')
    tmp = dest.with_suffix(dest.suffix + '.part')
    err = None
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r, open(tmp, 'wb') as out:
                shutil.copyfileobj(r, out, 1 << 20)
            tmp.replace(dest)
            return sha256_of(dest)
        except Exception as ex:  # noqa: BLE001 - any failure falls back to curl
            err = ex
            time.sleep(3)
    curl = shutil.which('curl') or 'curl'
    p = run([curl, '-L', '--fail', '--proto', '=https', '--retry', '3', '--connect-timeout', '30',
             '-A', UA['User-Agent'], '-o', str(tmp), url], timeout=3600)
    if p.returncode or not tmp.exists():
        raise RuntimeError(f'urllib: {err}; curl: {p.stderr.strip()[-150:]}')
    tmp.replace(dest)
    return sha256_of(dest)


def defender(path):
    exe = settings.defender()
    if not exe.exists():
        return 'defender unavailable'
    p = run([str(exe), '-Scan', '-ScanType', '3', '-File', str(path), '-DisableRemediation'], timeout=1800)
    if p.returncode == 0:
        return 'clean'
    if p.returncode == 2:
        return 'THREAT: ' + ' '.join(line for line in p.stdout.splitlines() if 'Threat' in line)[:300]
    return f'error {p.returncode}: {p.stdout.strip()[-200:]}'


def remove_tree(dst):
    r"""rmtree that copes with read-only .git objects and long paths; falls back to cmd's rmdir with \\?\ on Windows."""
    def clear_readonly(fn, path, _exc):
        try:
            os.chmod(path, stat.S_IWRITE)
            fn(path)
        except OSError:
            pass
    shutil.rmtree(dst, onerror=clear_readonly)
    if dst.exists() and sys.platform == 'win32':
        subprocess.run(['cmd', '/c', 'rmdir', '/s', '/q', '\\\\?\\' + str(dst)], capture_output=True)
    if dst.exists():
        raise RuntimeError(f'could not delete the previous clone: {dst}')


def clone(url, dst):
    # core.longpaths: repos with thousands of files fail the checkout on Windows without it
    p = run(['git', '-c', 'core.longpaths=true', 'clone', '--depth', '1', '--single-branch', url, str(dst)], timeout=1800)
    if p.returncode:
        raise RuntimeError('git clone: ' + p.stderr.strip()[-200:])
    return run(['git', '-C', str(dst), 'rev-parse', 'HEAD']).stdout.strip()


# ---------------------------------------------------------------- one entry

def process(e, update=False, root=None):
    root = root or settings.library_root()
    folder = root / e['category'] / e['id']
    folder.mkdir(parents=True, exist_ok=True)
    vfile = folder / 'verification.json'
    previous = json.loads(vfile.read_text('utf-8')) if vfile.exists() else None
    src = e['source']
    info = dict(id=e['id'], name=e['name'], category=e['category'], alternative_to=e.get('alternative_to'),
                repo=e.get('repo'), license=e.get('license'), notes=e.get('notes'), type=src['type'],
                date=time.strftime('%Y-%m-%d %H:%M'))
    if src['type'] == 'clone':
        dst = folder / 'code'
        if dst.exists() and previous and not update:  # clone present and already verified
            return previous
        if dst.exists():
            remove_tree(dst)
        info['commit'] = clone(src.get('url') or f"https://github.com/{e['repo']}.git", dst)
        info['sha256'] = 'n/a (git clone, integrity by commit hash)'
        info['defender'] = defender(dst)
        info['scanner'] = scanner.scan_and_report(dst)
    else:
        res = RESOLVERS[src['type']](src)
        target = folder / res['name']
        if previous and previous.get('file') == res['name'] and target.exists() and not update:
            return previous
        info.update(version=res['version'], url=res['url'], file=res['name'])
        got = download(res['url'], target)
        info['sha256'] = got
        if res['sha256']:
            info['sha256_official'] = res['sha256']
            info['sha256_ok'] = got.lower() == res['sha256'].lower()
            if not info['sha256_ok']:
                target.rename(target.with_name(target.name + '.QUARANTINE'))
        else:
            info['sha256_ok'] = None  # the source publishes no checksum
        info['defender'] = defender(target) if target.exists() else 'not scanned (quarantined before the scan)'
        for old in folder.iterdir():  # drop older versions of the same program
            if old.is_file() and old.name != res['name'] and old.name not in KEEP and not old.name.endswith('.QUARANTINE'):
                old.unlink()
    info['verdict'] = quarantine(info, folder, root)
    vfile.write_text(json.dumps(info, ensure_ascii=False, indent=2), 'utf-8')
    return info


def is_threat(info):
    return str(info.get('defender', '')).startswith('THREAT')


def quarantine(info, folder, root):
    """The policy: anything suspicious goes to _quarantine. If a clone can be cleaned by removing only the
    guilty files, it is cleaned and the removal is recorded; otherwise the entry is not kept."""
    scan = info.get('scanner') or {}
    suspicious = is_threat(info) or info.get('sha256_ok') is False or scan.get('high', 0) > 0
    if not suspicious:
        return 'clean'
    qroot = root / '_quarantine'
    q = qroot / folder.name
    if info['type'] == 'clone' and not is_threat(info):
        # only files with clear malware patterns are removed; high entropy alone is a warning, not proof
        guilty = sorted({f[2] for f in scan.get('high_detail', []) if f[1] != scanner.ENTROPY_LABEL})
        if not guilty:
            info['manual_review'] = list(scan.get('high_detail', []))
            return 'REVIEW: entropy warnings only (possible false positive), kept'
        for rel in guilty:
            f = folder / 'code' / rel
            if f.exists():
                q.mkdir(parents=True, exist_ok=True)
                shutil.move(str(f), str(q / rel.replace('/', '__').replace(os.sep, '__')))
        info['scanner'] = scanner.scan_and_report(folder / 'code')
        if info['scanner'].get('high', 0) == 0:
            info['removed_files'] = guilty
            return f'CLEANED: moved {len(guilty)} file(s) to _quarantine; check by hand that it still works'
    # cannot be cleaned: the whole folder is moved aside and nothing is kept
    qroot.mkdir(parents=True, exist_ok=True)
    if q.exists():
        shutil.rmtree(q, ignore_errors=True)
    shutil.move(str(folder), str(q))
    folder.mkdir(parents=True, exist_ok=True)
    return 'NOT KEPT: moved to _quarantine (could not be cleaned)'


# ---------------------------------------------------------------- report

SHA_TEXT = {True: 'OK', False: '**MISMATCH**', None: 'no official checksum'}


def report(root=None):
    root = root or settings.library_root()
    rows = [json.loads(v.read_text('utf-8')) for v in sorted(root.glob('*/*/verification.json'))
            if v.parent.parent.name != '_quarantine']
    lines = ['# Open-source programs and plugins', '',
             f'Generated by `fetch.py` on {time.strftime("%Y-%m-%d %H:%M")}. '
             'Verification: SHA256 against the official source, Microsoft Defender, and static analysis (scanner.py) of cloned code.', '']
    cat = None
    for i in sorted(rows, key=lambda x: (x['category'], x['name'].lower())):
        if i['category'] != cat:
            cat = i['category']
            lines += ['', f'## {cat}', '', '| Program | Replaces | Version | SHA256 | Defender | Scanner | Verdict | Notes |',
                      '|---|---|---|---|---|---|---|---|']
        sha = SHA_TEXT[i['sha256_ok']] if 'sha256_ok' in i else 'commit ' + (i.get('commit') or '')[:8]
        sc = i.get('scanner')
        sc_t = '-' if not sc else (f"{sc.get('high', 0)} high / {sc.get('medium', 0)} medium" if 'high' in sc else 'error')
        name = f"[{i['name']}](https://github.com/{i['repo']})" if i.get('repo') else i['name']
        lines.append(f"| {name} | {i.get('alternative_to') or ''} | {i.get('version') or ''} | {sha} | {i.get('defender', '')} | "
                     f"{sc_t} | {i.get('verdict', '')} | {(i.get('notes') or '').replace('|', '/')} |")
    root.mkdir(parents=True, exist_ok=True)
    (root / 'REPORT.md').write_text('\n'.join(lines) + '\n', 'utf-8')
    return len(rows)


def select(catalog, only=None, category=None):
    only = set(only.split(',')) if only else None
    return [e for e in catalog if (not only or e['id'] in only) and (not category or e['category'].startswith(category))]


def main(argv=None):
    ap = argparse.ArgumentParser(description='Download, verify and scan the programs of the catalog.')
    ap.add_argument('--only', help='comma-separated ids')
    ap.add_argument('--category', help='category prefix, e.g. 01_video')
    ap.add_argument('--update', action='store_true', help='fetch the latest version again')
    ap.add_argument('--report', action='store_true', help='only rebuild REPORT.md')
    a = ap.parse_args(argv)
    if not a.report:
        for e in select(settings.load_catalog(), a.only, a.category):
            t0 = time.time()
            try:
                i = process(e, a.update)
                sc = {k: v for k, v in (i.get('scanner') or {}).items() if k in ('high', 'medium')}
                print(f"OK   {e['category']}/{e['id']}  {i.get('version', '')}  sha={i.get('sha256_ok')}  "
                      f"defender={i.get('defender')}  scan={sc}  {time.time() - t0:.0f}s", flush=True)
            except Exception as ex:  # noqa: BLE001 - one broken entry must not stop the batch
                print(f"FAIL {e['category']}/{e['id']}: {ex}", flush=True)
    print('report:', report(), 'entries')


if __name__ == '__main__':
    main()
