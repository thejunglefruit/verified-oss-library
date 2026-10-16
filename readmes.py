# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Writes a README.md inside each program/plugin folder of the library.

Combines: the catalog (name, what it replaces, license, notes), an optional recommendations.json
(what it is for and usage tips, written by hand), the GitHub description (cached in
<library>/descriptions.json) and verification.json (SHA256, Defender, scanner) -> a safety level.

Usage: python readmes.py               # every folder with a verification.json
       python readmes.py --only id1,id2
"""
import argparse
import json
import subprocess

import settings

LEVELS_HELP = ('How to read the level: GREEN = official origin verified and nothing found; YELLOW = usable but with '
               'something to review (no official checksum, bundled binaries or scanner warnings); RED = do not use.')


def description(repo, cache):
    if not repo:
        return ''
    if repo not in cache:
        p = subprocess.run(['gh', 'api', f'repos/{repo}', '--jq', '.description'], capture_output=True, text=True, encoding='utf-8')
        cache[repo] = p.stdout.strip() if p.returncode == 0 else ''
    return cache[repo]


def safety_level(v):
    """GREEN / YELLOW / RED from a verification.json, plus the reasons in one sentence."""
    if not v:
        return 'UNVERIFIED', 'Not downloaded or analysed yet.'
    reasons = []
    d = str(v.get('defender', ''))
    sc = v.get('scanner') or {}
    clone = v.get('type') == 'clone'
    if d.startswith('THREAT') or v.get('sha256_ok') is False or str(v.get('verdict', '')).startswith('NOT KEPT'):
        return 'RED', 'Defender found a threat or the SHA256 does not match the official one. Do not use.'
    if v.get('sha256_ok') is True:
        reasons.append('SHA256 matches the one published by the official source')
    elif v.get('sha256_ok') is None and not clone:
        reasons.append('the source publishes no checksum (verified only by HTTPS from the official site and Defender)')
    if clone:
        reasons.append(f"git clone of the official repository (commit {v.get('commit', '')[:10]})")
    if d == 'clean':
        reasons.append('Microsoft Defender: clean')
    if sc:
        reasons.append(f"static analysis: {sc.get('high', 0)} high, {sc.get('medium', 0)} medium findings ({sc.get('files', 0)} files)")
    level = 'GREEN'
    if sc.get('high', 0) > 0 or (v.get('sha256_ok') is None and not clone) or str(v.get('verdict', '')).startswith(('CLEANED', 'REVIEW')):
        level = 'YELLOW'
    if sc.get('n_binaries', 0) > 0:
        reasons.append(f"contains {sc['n_binaries']} prebuilt binaries inside the repo (cannot be audited as code)")
        level = 'YELLOW' if level == 'GREEN' else level
    return level, '; '.join(reasons) + '.'


def readme(e, root, recs, cache):
    folder = root / e['category'] / e['id']
    vf = folder / 'verification.json'
    v = json.loads(vf.read_text('utf-8')) if vf.exists() else None
    r = recs.get(e['id'], {})
    level, reason = safety_level(v)
    url = f"https://github.com/{e['repo']}" if e.get('repo') else (e['source'].get('url') or '')
    version = (v or {}).get('version') or (v or {}).get('commit', '')[:10] or 'pending'
    lines = [f"# {e['name']}", '',
             f"**Replaces:** {e.get('alternative_to') or '-'}  ", f"**License:** {e.get('license') or 'see repository'}  ",
             f"**Official source:** {url}  ", f"**Version downloaded:** {version}  ", f"**Safety level:** {level}", '',
             '## What it is for', '', r.get('purpose') or description(e.get('repo'), cache) or (e.get('notes') or ''), '',
             '## Usage tips', '']
    lines += [f'- {x}' for x in r.get('usage', [])] or ['- ' + (e.get('notes') or 'See the project documentation.')]
    if e.get('notes') and r.get('usage'):
        lines += [f"- Note: {e['notes']}"]
    lines += ['', '## Safety', '', reason, '']
    if v:
        if v.get('file'):
            lines += [f"- File: `{v['file']}`", f"- SHA256: `{v.get('sha256', '')}`"]
        if v.get('verdict'):
            lines += [f"- Verdict: {v['verdict']}"]
        if v.get('removed_files'):
            lines += [f"- Files moved to `_quarantine`: {', '.join(v['removed_files'])}"]
        if v.get('type') == 'clone':
            lines += ['- Static analysis details in `SCAN.md` (same folder).']
        lines += [f"- Verified on {v.get('date', '')} with `fetch.py`."]
    lines += ['', LEVELS_HELP, '']
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'README.md').write_text('\n'.join(lines), 'utf-8')
    return level


def main(argv=None):
    ap = argparse.ArgumentParser(description='Write a README.md with a safety level in each program folder.')
    ap.add_argument('--only', help='comma-separated ids')
    a = ap.parse_args(argv)
    only = set(a.only.split(',')) if a.only else None
    root = settings.library_root()
    recs = settings.recommendations()
    cache_f = root / 'descriptions.json'
    cache = json.loads(cache_f.read_text('utf-8')) if cache_f.exists() else {}
    counts = {}
    for e in settings.load_catalog():
        if only and e['id'] not in only:
            continue
        if not only and not (root / e['category'] / e['id'] / 'verification.json').exists():
            continue
        level = readme(e, root, recs, cache)
        counts[level] = counts.get(level, 0) + 1
    if cache:
        root.mkdir(parents=True, exist_ok=True)
        cache_f.write_text(json.dumps(cache, ensure_ascii=False, indent=1), 'utf-8')
    print('READMEs:', counts)


if __name__ == '__main__':
    main()
