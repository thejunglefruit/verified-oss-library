# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
r"""Analyses the code of one repository (or of every clone in the library) and turns it into notes.

For each `code/` folder it writes, in the program's folder:
  analysis.json  languages, size, entry points (CLI, npm scripts, entry_points), dependencies, license,
                 README summary, security findings (semgrep p/security-audit + p/secrets) and vulnerable
                 dependencies (pip-audit / npm audit when there is a lockfile)
  ANALYSIS.md    the same, readable

Usage:
  python analyzer.py                              # every clone in the library
  python analyzer.py --only rhubarb,duik
  python analyzer.py --path some/project --out some/report   # any folder
  python analyzer.py --no-semgrep                 # structure only (fast)
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import settings

SKIP = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', 'vendor', 'third_party', 'thirdparty', '.next', 'target'}
LANG = {'.py': 'Python', '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
        '.lua': 'Lua', '.fuse': 'Lua (Fuse)', '.jsfl': 'JSFL', '.jsxbin': 'ExtendScript (compiled)', '.cpp': 'C++', '.cc': 'C++', '.c': 'C',
        '.h': 'C/C++', '.hpp': 'C++', '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.kt': 'Kotlin', '.cs': 'C#', '.swift': 'Swift',
        '.php': 'PHP', '.rb': 'Ruby', '.sh': 'Shell', '.ps1': 'PowerShell', '.glsl': 'GLSL', '.frag': 'GLSL', '.vert': 'GLSL',
        '.wgsl': 'WGSL', '.cu': 'CUDA', '.html': 'HTML', '.css': 'CSS', '.scss': 'SCSS', '.vue': 'Vue', '.svelte': 'Svelte',
        '.gd': 'GDScript', '.d': 'D', '.ex': 'Elixir', '.scad': 'OpenSCAD', '.nk': 'Nuke', '.gizmo': 'Nuke gizmo',
        '.setting': 'Fusion', '.comp': 'Fusion'}
KEY_FILES = ('setup.py', 'pyproject.toml', 'requirements.txt', 'package.json', 'cargo.toml', 'cmakelists.txt', 'go.mod',
             'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'environment.yml', 'manifest.json')
LICENSES = (('MIT', r'MIT License'), ('Apache-2.0', r'Apache License'), ('GPL-3.0', r'GNU GENERAL PUBLIC LICENSE\s+Version 3'),
            ('GPL-2.0', r'GNU GENERAL PUBLIC LICENSE\s+Version 2'), ('AGPL-3.0', r'GNU AFFERO'), ('LGPL', r'GNU LESSER'),
            ('BSD', r'Redistribution and use in source and binary forms'), ('MPL-2.0', r'Mozilla Public License'),
            ('CC-BY-NC', r'NonCommercial'), ('CC0', r'CC0'), ('Unlicense', r'unlicense'), ('zlib', r'zlib License'))


def run(cmd, timeout=1800, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout, cwd=cwd)


def structure(root):
    langs, n, size, jsx = Counter(), 0, 0, 0
    key = {}
    for p in root.rglob('*'):
        rel = p.relative_to(root)
        if any(part in SKIP for part in rel.parts[:-1]) or not p.is_file():
            continue
        n += 1
        try:
            size += p.stat().st_size
        except OSError:
            pass
        e = p.suffix.lower()
        if e == '.jsx':  # Adobe ExtendScript or React: cannot tell from the extension
            jsx += 1
        if e in LANG:
            langs[LANG[e]] += 1
        nm = p.name.lower()
        if len(rel.parts) <= 2 and nm in KEY_FILES:
            key.setdefault(nm, rel.as_posix())
        if len(rel.parts) == 1 and re.match(r'(?i)(readme|license|licence|copying)(\..*)?$', nm):
            key.setdefault(re.sub(r'\..*', '', nm), rel.as_posix())
    if jsx:
        langs['JSX (ExtendScript or React)'] += jsx
    return dict(files=n, size_mb=round(size / 1048576, 1), languages=langs.most_common(8), key_files=key)


def read(p, n=20000):
    try:
        return Path(p).read_text('utf-8', errors='replace')[:n]
    except OSError:
        return ''


def entry_points(root, key):
    ep = {}
    if 'package.json' in key:
        try:
            pj = json.loads(read(root / key['package.json'], 200000))
            if pj.get('bin'):
                ep['npm bin'] = pj['bin']
            if pj.get('scripts'):
                ep['npm scripts'] = {k: v[:100] for k, v in list(pj['scripts'].items())[:12]}
            ep['npm dependencies'] = len(pj.get('dependencies', {}))
            ep['npm name'] = pj.get('name')
        except ValueError:
            pass
    if 'pyproject.toml' in key:
        t = read(root / key['pyproject.toml'], 100000)
        m = re.search(r'\[project\.scripts\]\s*\n((?:\s*[\w\-\.]+\s*=\s*"[^"]+"\s*\n?)+)', t)
        if m:
            ep['python scripts'] = dict(re.findall(r'([\w\-\.]+)\s*=\s*"([^"]+)"', m.group(1)))
        m = re.search(r'dependencies\s*=\s*\[(.*?)\]', t, re.S)
        if m:
            ep['python dependencies'] = [d.strip(' "\',') for d in m.group(1).split('\n') if d.strip(' "\',')][:40]
    if 'setup.py' in key:
        t = read(root / key['setup.py'], 100000)
        m = re.search(r'console_scripts["\']?\s*:\s*\[(.*?)\]', t, re.S)
        if m:
            ep['console_scripts'] = [s.strip(' "\',') for s in m.group(1).split(',') if s.strip(' "\',')]
    if 'requirements.txt' in key:
        ep['requirements'] = [line.strip() for line in read(root / key['requirements.txt']).splitlines()
                              if line.strip() and not line.startswith('#')][:40]
    if 'cargo.toml' in key:
        ep['rust'] = True
    if 'cmakelists.txt' in key:
        ep['cmake'] = True
    if {'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'} & set(key):
        ep['docker'] = True
    # loose scripts at the root (jsx, jsfl, lua, py) = plugins that are copied as they are
    loose = [p.name for p in root.iterdir() if p.is_file() and p.suffix.lower() in ('.jsx', '.jsfl', '.lua', '.fuse', '.py', '.gizmo', '.nk')]
    if loose:
        ep['scripts at root'] = loose[:30]
    return ep


def readme_summary(root, key):
    r = key.get('readme')
    if not r:
        return ''
    t = read(root / r, 60000)
    t = re.sub(r'<[^>]+>', '', t)                    # html
    t = re.sub(r'!\[[^\]]*\]\([^)]*\)', '', t)       # images
    t = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', t)   # links
    paras = [p.strip() for p in re.split(r'\n\s*\n', t) if len(p.strip()) > 60 and not p.strip().startswith(('#', '|', '```', '-', '*'))]
    return '\n\n'.join(paras[:3])[:1500]


def license_of(root, key):
    for k in ('license', 'licence', 'copying'):
        if k in key:
            t = read(root / key[k], 3000)
            for name, pat in LICENSES:
                if re.search(pat, t, re.I):
                    return name
            return 'other: ' + t.strip().splitlines()[0][:80] if t.strip() else 'empty file'
    return 'no license file'


def semgrep(root):
    if not shutil.which('semgrep'):
        return {'error': 'semgrep is not installed'}
    out = Path(tempfile.gettempdir()) / f'semgrep_{int(time.time() * 1000)}.json'
    p = run(['semgrep', '--config', 'p/security-audit', '--config', 'p/secrets', '--metrics=off', '--quiet', '--json', '-o', str(out),
             '--timeout', '30', '--max-target-bytes', '1500000', str(root)], timeout=2400)
    try:
        d = json.loads(out.read_text('utf-8'))
    except (OSError, ValueError):
        return {'error': (p.stderr or p.stdout)[-300:]}
    finally:
        out.unlink(missing_ok=True)
    res = d.get('results', [])
    order = {'ERROR': 0, 'WARNING': 1}
    top = [dict(rule=r['check_id'].split('.')[-1], sev=r['extra'].get('severity'),
                file=str(Path(r['path']).relative_to(root)) if str(r['path']).startswith(str(root)) else r['path'],
                line=r['start']['line'], msg=r['extra'].get('message', '')[:200])
           for r in sorted(res, key=lambda r: order.get(r['extra'].get('severity'), 2))[:25]]
    return dict(total=len(res), by_severity=dict(Counter(r['extra'].get('severity', '?') for r in res)),
                by_rule=Counter(r['check_id'].split('.')[-1] for r in res).most_common(15), top=top,
                semgrep_errors=len(d.get('errors', [])))


def vulnerable_deps(root, key):
    """Dependencies with known CVEs: pip-audit on requirements, npm audit when there is a package-lock."""
    r = {}
    if 'requirements.txt' in key:
        p = run([sys.executable, '-m', 'pip_audit', '-r', str(root / key['requirements.txt']), '--format', 'json',
                 '--progress-spinner', 'off', '--disable-pip'], timeout=900)
        try:
            d = json.loads(p.stdout)
            vul = [dict(package=x['name'], version=x.get('version'), ids=[v['id'] for v in x.get('vulns', [])][:5],
                        fix=[f for v in x.get('vulns', []) for f in v.get('fix_versions', [])][:3])
                   for x in d.get('dependencies', []) if x.get('vulns')]
            r['pip'] = dict(vulnerable=vul, n=len(vul))
        except ValueError:
            r['pip'] = {'error': (p.stderr or p.stdout)[-200:]}
    if (root / 'package-lock.json').exists():
        npm = shutil.which('npm') or 'npm'
        p = run([npm, 'audit', '--json', '--audit-level=moderate', '--package-lock-only'], timeout=900, cwd=str(root))
        try:
            d = json.loads(p.stdout)
            meta = d.get('metadata', {}).get('vulnerabilities', {})
            r['npm'] = dict(by_severity=meta, n=sum(v for k, v in meta.items() if k != 'total' and isinstance(v, int)),
                            top=[dict(package=k, sev=v.get('severity'), via=[x.get('title') if isinstance(x, dict) else x for x in v.get('via', [])[:2]])
                                 for k, v in list(d.get('vulnerabilities', {}).items())[:15]])
        except ValueError:
            r['npm'] = {'error': (p.stderr or p.stdout)[-200:]}
    return r


def analyse(root, out, name, with_semgrep=True):
    root, out = Path(root), Path(out)
    t0 = time.time()
    st = structure(root)
    a = dict(name=name, path=root.name, date=time.strftime('%Y-%m-%d %H:%M'), **st)
    a['license_detected'] = license_of(root, st['key_files'])
    a['entry_points'] = entry_points(root, st['key_files'])
    a['readme'] = readme_summary(root, st['key_files'])
    if with_semgrep:
        a['semgrep'] = semgrep(root)
        a['vulnerable_deps'] = vulnerable_deps(root, st['key_files'])
    a['seconds'] = round(time.time() - t0)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'analysis.json').write_text(json.dumps(a, ensure_ascii=False, indent=1, default=str), 'utf-8')
    (out / 'ANALYSIS.md').write_text(to_markdown(a), 'utf-8')
    return a


def to_markdown(a):
    lines = [f"# Code analysis: {a['name']}", '',
             f"{a['files']} files · {a['size_mb']} MB · license detected: {a['license_detected']} · {a['date']}", '',
             '## Languages', '', ', '.join(f'{lang} ({n})' for lang, n in a['languages']) or '-', '']
    if a.get('readme'):
        lines += ['## What its README says', '', a['readme'], '']
    ep = a.get('entry_points') or {}
    if ep:
        lines += ['## Entry points and dependencies', '']
        for k, v in ep.items():
            if isinstance(v, dict):
                lines += [f'- **{k}**: ' + ', '.join(f'`{kk}` → `{vv}`' for kk, vv in list(v.items())[:12])]
            elif isinstance(v, list):
                lines += [f'- **{k}**: ' + ', '.join(f'`{x}`' for x in v[:25])]
            else:
                lines += [f'- **{k}**: {v}']
        lines += ['']
    sg = a.get('semgrep')
    if sg:
        lines += ['## Security (semgrep p/security-audit + p/secrets)', '']
        if 'error' in sg:
            lines += [f"Error: {sg['error']}", '']
        else:
            lines += [f"Findings: {sg['total']} · by severity: {sg['by_severity']}", '']
            if sg['by_rule']:
                lines += ['Most frequent rules: ' + ', '.join(f'{r} ({n})' for r, n in sg['by_rule'][:10]), '']
            lines += [f"- [{t['sev']}] `{t['file']}:{t['line']}` {t['rule']}: {t['msg']}" for t in sg['top'][:15]] + ['']
    dv = a.get('vulnerable_deps') or {}
    if dv:
        lines += ['## Dependencies with known vulnerabilities', '']
        for eco, r in dv.items():
            if 'error' in r:
                lines += [f'- {eco}: could not check ({r["error"][:120]})']
            elif eco == 'pip':
                lines += [f"- pip-audit: {r['n']} vulnerable packages"] + [
                    f"  - {v['package']} {v['version']}: {', '.join(v['ids'])} (fix: {', '.join(v['fix']) or '?'})" for v in r['vulnerable'][:15]]
            else:
                lines += [f"- npm audit: {r['n']} ({r['by_severity']})"] + [
                    f"  - {v['package']} [{v['sev']}]: {'; '.join(str(x) for x in v['via'])}" for v in r['top'][:15]]
        lines += ['']
    lines += ['Note: semgrep flags patterns (subprocess, eval, dynamic SQL, secrets...) that can be legitimate; '
              'ERROR findings and dependencies with CVEs are what to review first.', '']
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Structure, license, entry points and security notes for cloned code.')
    ap.add_argument('--only', help='comma-separated ids')
    ap.add_argument('--path', help='analyse any folder instead of the library')
    ap.add_argument('--out', help='where to write analysis.json / ANALYSIS.md (default: --path)')
    ap.add_argument('--no-semgrep', action='store_true')
    a = ap.parse_args(argv)
    if a.path:
        r = analyse(a.path, a.out or a.path, Path(a.path).name, not a.no_semgrep)
        print(json.dumps({k: r[k] for k in ('files', 'size_mb', 'license_detected', 'seconds')}), (r.get('semgrep') or {}).get('total'))
        return
    only = set(a.only.split(',')) if a.only else None
    for code in sorted(settings.library_root().glob('*/*/code')):
        pid = code.parent.name
        if (only and pid not in only) or code.parent.parent.name == '_quarantine':
            continue
        if (code.parent / 'analysis.json').exists() and not only:
            continue
        try:
            r = analyse(code, code.parent, pid, not a.no_semgrep)
            sg = r.get('semgrep') or {}
            print(f"OK   {code.parent.parent.name}/{pid}: {r['files']} files, {r['license_detected']}, "
                  f"semgrep={sg.get('total', '-')} {sg.get('by_severity', '')}, {r['seconds']}s", flush=True)
        except Exception as ex:  # noqa: BLE001
            print(f'FAIL {code.parent.parent.name}/{pid}: {ex}', flush=True)


if __name__ == '__main__':
    main()
