# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Static code scanner: looks for typical malware patterns in scripts, plugins and projects.

It does not replace an audit: it marks what a human (or an agent) has to look at.
  HIGH   -> a pattern that is almost never legitimate in a creative plugin (obfuscated payload, credential
            theft, system persistence, reverse shell, exfiltration to webhooks/Telegram, download-and-run).
  MEDIUM -> often legitimate but risky (running commands, eval, network access, binaries inside a script repo).

Some literal words below are written with a one-letter character class (e.g. `Meta[M]ask`). The regex
means exactly the same, but this file no longer matches its own patterns when it is scanned.

Usage: python scanner.py <folder> [--json] [--max 40]
Also writes <folder>/../SCAN.md with the findings.
"""
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', 'third_party', 'thirdparty',
             'extern', 'external', 'vendor'}
TEXT = {'.py', '.js', '.mjs', '.cjs', '.ts', '.jsx', '.jsxbin', '.jsfl', '.lua', '.fuse', '.setting', '.sh', '.bat', '.cmd',
        '.ps1', '.psm1', '.vbs', '.rb', '.php', '.nk', '.gizmo', '.json', '.xml', '.html', '.htm', '.cpp', '.c', '.h', '.hpp',
        '.cs', '.rs', '.go', '.java', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.txt', '.mel', '.tcl'}
BINARIES = {'.exe', '.dll', '.scr', '.msi', '.com', '.pif', '.cpl', '.sys', '.jar', '.aex', '.8bf', '.zxp'}
MAX_TEXT_BYTES = 2_000_000

HIGH = [
    ('encoded powershell', r'(?i)powershell[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}'),
    ('base64 -> execute (PS)', r'(?i)(FromBase64Strin[g][^\n]{0,200}(Invoke-Expression|IEX\b)|(Invoke-Expression|IEX)\s*\(?\s*\[?[^\n]{0,60}FromBase6[4])'),
    ('base64/zlib -> exec (Py)', r'(?i)exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode)'),
    ('eval of base64 (JS)', r'(?i)eval\s*\(\s*(atob|Buffer\.from\([^)]*base64|unescape\s*\()'),
    ('Function() from obfuscated string', r'new\s+Function\s*\(\s*(atob|unescape|String\.fromCharCode)'),
    # the official Rust and uv installers (piped into a shell) appear in the CI of many honest repos: accepted
    ('download and run', r'(?i)(curl|wget|iwr|Invoke-WebRequest)(?![^\n|]{0,200}(sh\.rustup\.rs|astral\.sh/))[^\n|]{0,200}\|\s*(sh|bash|iex|python)\b'
                         r'|certuti[l][^\n]{0,40}-urlcache|bitsadmi[n][^\n]{0,40}/transfer|mshta\s+https?:'),
    ('persistence (Run key / tasks)', r'(?i)(CurrentVersion\\\\?Run\b|schtask[s][^\n]{0,20}/create|New-Scheduled[T]ask|Startup\\\\?[^\n]{0,40}\.(lnk|exe|bat|vbs))'),
    # the name of Chrome's key file is matched case-sensitively on purpose: in lower case it is a common phrase in code comments
    ('browser credential theft', r'(?i:Login[ ]Data|cookies\.sqlite|logins\.json|Crypt[U]nprotectData|\\\\Google\\\\Chrome\\\\User Data)|\bLocal[ ]State\b'),
    ('crypto wallets', r'(?i)(wallet\.dat|Exodus\\\\exodus|Meta[M]ask|\\\\Electrum\\\\wallets)'),
    ('webhook exfiltration', r'(?i)(discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|pastebin\.com/raw|transfer\.sh|ngrok\.io)'),
    ('reverse shell', r'(?i)(socket\.socket[^\n]{0,200}(subprocess|pty\.spawn|/bin/sh)|nc\s+-e\s+/bin|/dev/tcp/\d)'),
    ('keylogger', r'(?i)(GetAsync[K]eyState|SetWindows[H]ookEx[^\n]{0,30}WH_KEYBOARD|pynput\.keyboard\.Listener)'),
    ('antivirus tampering', r'(?i)(Set-Mp[P]reference[^\n]{0,60}-Disable|Add-Mp[P]reference[^\n]{0,30}-ExclusionPath)'),
]
MEDIUM = [
    ('runs system commands', r'(?i)(subprocess\.(Popen|run|call|check_output)|os\.system\(|child_process|system\.callSystem|app\.system\(|WScript\.Shell|Shell\.Application|ShellExecute|os\.popen)'),
    ('dynamic eval', r'(?<![\w.])eval\s*\('),
    ('outbound network', r'(?i)(requests\.(get|post)|urllib\.request|fetch\s*\(\s*[\'"`]https?:|XMLHttpRequest|socket\.connect|new\s+Socket\(|http\.request\()'),
    ('native library loading', r'(?i)(ctypes\.(windll|cdll|CDLL)|ExternalObject\s*\(|LoadLibrary)'),
]
HIGH = [(n, re.compile(p)) for n, p in HIGH]
MEDIUM = [(n, re.compile(p)) for n, p in MEDIUM]
DOMAIN = re.compile(r'https?://([a-zA-Z0-9.-]+\.[a-z]{2,})')
ENTROPY_LABEL = 'long high-entropy line (possible obfuscation)'
EMBEDDED_ASSET = re.compile(r'data:(image|font|application/(font|octet))|\.(png|jpg|woff2?|ttf)\b|sourceMappingURL')


def entropy(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def scan(root, extra_skip=()):
    """extra_skip: more folder names not to enter (build outputs, copies of other repos...)."""
    root = Path(root)
    skip = SKIP_DIRS | set(extra_skip)
    findings, domains, binaries, n = [], Counter(), [], 0
    for p in root.rglob('*'):
        if any(part in skip for part in p.relative_to(root).parts[:-1]) or not p.is_file():
            continue
        ext = p.suffix.lower()
        rel = p.relative_to(root).as_posix()
        if ext in BINARIES:
            binaries.append(rel)
            continue
        if ext not in TEXT or p.stat().st_size > MAX_TEXT_BYTES:
            continue
        n += 1
        try:
            txt = p.read_text('utf-8', errors='replace')
        except OSError:
            continue
        minified = p.name.endswith('.min.js') or ext in ('.json', '.jsxbin')
        for i, line in enumerate(txt.splitlines(), 1):
            for name, rx in HIGH:
                if rx.search(line):
                    findings.append(('HIGH', name, rel, i, line.strip()[:160]))
            if not minified:
                for name, rx in MEDIUM:
                    if rx.search(line):
                        findings.append(('MEDIUM', name, rel, i, line.strip()[:160]))
                if (len(line) > 3000 and entropy(line[:5000]) > 5.3
                        and ext not in ('.xml', '.html', '.htm', '.nk', '.gizmo', '.setting', '.txt')
                        and not EMBEDDED_ASSET.search(line[:400])):
                    findings.append(('HIGH', ENTROPY_LABEL, rel, i, line[:80]))
            for d in DOMAIN.findall(line):
                domains[d.lower()] += 1
        if ext == '.jsxbin':
            findings.append(('MEDIUM', 'jsxbin (compiled script, cannot be audited)', rel, 0, ''))
    return dict(files=n, high=sum(f[0] == 'HIGH' for f in findings), medium=sum(f[0] == 'MEDIUM' for f in findings),
                binaries=binaries[:50], n_binaries=len(binaries), findings=findings, domains=domains.most_common(40))


def summary(result, limit=30):
    """The short form stored in verification.json: counts, binaries, domains and the HIGH findings."""
    short = {k: v for k, v in result.items() if k != 'findings'}
    short['high_detail'] = [f for f in result['findings'] if f[0] == 'HIGH'][:limit]
    return short


def to_markdown(r, root, maxh=40):
    lines = [f'# Static scan: {Path(root).parent.name}', '',
             f"Text files analysed: {r['files']} · HIGH: {r['high']} · MEDIUM: {r['medium']} · binaries: {r['n_binaries']}", '']
    high = [f for f in r['findings'] if f[0] == 'HIGH']
    if high:
        lines += ['## HIGH (review by hand)', ''] + [f'- `{f[2]}:{f[3]}` **{f[1]}** — `{f[4]}`' for f in high[:maxh]] + ['']
    by_kind = Counter(f[1] for f in r['findings'] if f[0] == 'MEDIUM')
    if by_kind:
        lines += ['## MEDIUM (summary by kind)', ''] + [f'- {k}: {v}' for k, v in by_kind.most_common()] + ['']
    if r['binaries']:
        lines += ['## Binaries inside the repo', ''] + [f'- `{b}`' for b in r['binaries']] + ['']
    if r['domains']:
        lines += ['## Domains mentioned', ''] + [f'- {d} ({c})' for d, c in r['domains']] + ['']
    return '\n'.join(lines)


def scan_and_report(root):
    """Scan `root`, write SCAN.md next to it and return the short summary."""
    r = scan(root)
    (Path(root).parent / 'SCAN.md').write_text(to_markdown(r, root), 'utf-8')
    return summary(r)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith('-'):
        print(__doc__)
        return 2
    root = argv[0]
    maxh = int(argv[argv.index('--max') + 1]) if '--max' in argv else 40
    r = scan(root)
    (Path(root).parent / 'SCAN.md').write_text(to_markdown(r, root, maxh), 'utf-8')
    if '--json' in argv:
        print(json.dumps(summary(r), ensure_ascii=False))
    else:
        print(to_markdown(r, root, maxh))
    return 1 if r['high'] else 0


if __name__ == '__main__':
    sys.exit(main())
