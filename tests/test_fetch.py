# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""fetch.py end to end with fake sources: file:// downloads, fake GitHub/winget answers, fake git and Defender."""
import hashlib
import json
import types

import pytest

import fetch
from conftest import entry


@pytest.fixture
def clean_defender(monkeypatch):
    monkeypatch.setattr(fetch, 'defender', lambda path: 'clean')


def fake_file(tmp, name, data=b'portable program'):
    p = tmp / 'origin' / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p, hashlib.sha256(data).hexdigest()


def test_url_with_matching_sha_is_clean(lib, clean_defender):
    src, sha = fake_file(lib.tmp, 'tool.zip')
    e = entry('tool', dict(type='url', url=src.as_uri(), sha256=sha, version='1.0'))
    info = fetch.process(e)
    folder = lib.root / '01_test' / 'tool'
    assert info['sha256_ok'] is True and info['verdict'] == 'clean'
    assert (folder / 'tool.zip').read_bytes() == b'portable program'
    assert json.loads((folder / 'verification.json').read_text('utf-8'))['version'] == '1.0'


def test_sha_mismatch_goes_to_quarantine(lib, clean_defender):
    src, _ = fake_file(lib.tmp, 'tool.zip')
    e = entry('tool', dict(type='url', url=src.as_uri(), sha256='0' * 64))
    info = fetch.process(e)
    assert info['sha256_ok'] is False and info['verdict'].startswith('NOT KEPT')
    assert (lib.root / '_quarantine' / 'tool' / 'tool.zip.QUARANTINE').exists()
    assert not (lib.root / '01_test' / 'tool' / 'tool.zip').exists()


def test_no_official_checksum_is_recorded_as_none(lib, clean_defender):
    src, _ = fake_file(lib.tmp, 'tool.msi')
    info = fetch.process(entry('tool', dict(type='url', url=src.as_uri())))
    assert info['sha256_ok'] is None and info['verdict'] == 'clean'


def test_defender_threat_is_not_kept(lib, monkeypatch):
    monkeypatch.setattr(fetch, 'defender', lambda path: 'THREAT: Trojan:Win32/Fake')
    src, sha = fake_file(lib.tmp, 'tool.zip')
    info = fetch.process(entry('tool', dict(type='url', url=src.as_uri(), sha256=sha)))
    assert info['verdict'].startswith('NOT KEPT')


def test_plain_http_is_refused(lib):
    with pytest.raises(RuntimeError, match='refusing'):
        fetch.download('http://example.org/tool.zip', lib.tmp / 'tool.zip')


def test_second_run_reuses_and_update_replaces_old_versions(lib, clean_defender):
    v1, sha1 = fake_file(lib.tmp, 'tool-1.zip', b'one')
    fetch.process(entry('tool', dict(type='url', url=v1.as_uri(), sha256=sha1)))
    calls = []
    real = fetch.download
    fetch.download = lambda *a: calls.append(a) or real(*a)
    try:
        fetch.process(entry('tool', dict(type='url', url=v1.as_uri(), sha256=sha1)))
        assert calls == []                      # already verified: nothing downloaded
        v2, sha2 = fake_file(lib.tmp, 'tool-2.zip', b'two')
        fetch.process(entry('tool', dict(type='url', url=v2.as_uri(), sha256=sha2)), update=True)
    finally:
        fetch.download = real
    names = sorted(p.name for p in (lib.root / '01_test' / 'tool').iterdir())
    assert names == ['tool-2.zip', 'verification.json']


def test_resolve_gh_picks_asset_and_digest(monkeypatch):
    releases = [
        dict(draft=False, prerelease=True, tag_name='v3.0-beta', assets=[dict(name='app-win64.zip', browser_download_url='u0', size=1)]),
        dict(draft=False, prerelease=False, tag_name='v2.1', assets=[
            dict(name='app-linux.tar.gz', browser_download_url='u1', size=1),
            dict(name='app-win64.zip', browser_download_url='https://example.org/app-win64.zip', size=5, digest='sha256:' + 'ab' * 32)]),
    ]
    monkeypatch.setattr(fetch, 'gh_json', lambda path: releases)
    r = fetch.resolve_gh(dict(repo='o/app', asset=r'win64\.zip$'))
    assert (r['version'], r['sha256'], r['name']) == ('v2.1', 'ab' * 32, 'app-win64.zip')
    assert fetch.resolve_gh(dict(repo='o/app', asset=r'win64\.zip$', prerelease=True))['version'] == 'v3.0-beta'
    with pytest.raises(RuntimeError):
        fetch.resolve_gh(dict(repo='o/app', asset=r'\.dmg$'))


@pytest.mark.parametrize('text', [
    'Version: 1.2.3\nInstaller Url: https://example.org/files/app.exe/download\nInstaller SHA256: ' + 'AB' * 32,
    'Versión: 1.2.3\nURL del instalador: https://example.org/files/app.exe/download\nInstalador SHA256: ' + 'AB' * 32,
])
def test_resolve_winget_reads_english_and_spanish_output(monkeypatch, text):
    monkeypatch.setattr(fetch, 'run', lambda cmd, **kw: types.SimpleNamespace(stdout=text, returncode=0))
    r = fetch.resolve_winget(dict(id='Vendor.App'))
    assert (r['name'], r['version'], r['sha256']) == ('app.exe', '1.2.3', 'ab' * 32)


def fake_clone(files):
    def clone(url, dst):
        for rel, text in files.items():
            p = dst / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, 'utf-8')
        return 'f' * 40
    return clone


def test_clone_with_one_bad_file_is_cleaned(lib, clean_defender, monkeypatch):
    bad = 'import os\nos.startfile("x")\nURL = "https://api.telegram.org/' + 'bot123/sendMessage"\n'
    monkeypatch.setattr(fetch, 'clone', fake_clone({'plugin.jsx': 'alert(1);\n', 'tools/send.py': bad}))
    info = fetch.process(entry('plug', dict(type='clone'), repo='o/plug'))
    assert info['verdict'].startswith('CLEANED') and info['removed_files'] == ['tools/send.py']
    assert info['scanner']['high'] == 0 and info['commit'] == 'f' * 40
    assert (lib.root / '_quarantine' / 'plug' / 'tools__send.py').exists()
    assert (lib.root / '01_test' / 'plug' / 'code' / 'plugin.jsx').exists()
    assert (lib.root / '01_test' / 'plug' / 'SCAN.md').exists()


def test_clean_clone_and_report(lib, clean_defender, monkeypatch):
    monkeypatch.setattr(fetch, 'clone', fake_clone({'index.js': 'export const x = 1;\n'}))
    fetch.process(entry('plug', dict(type='clone'), repo='o/plug', notes='a|b'))
    src, sha = fake_file(lib.tmp, 'tool.zip')
    fetch.process(entry('tool', dict(type='url', url=src.as_uri(), sha256=sha)))
    assert fetch.report() == 2
    text = (lib.root / 'REPORT.md').read_text('utf-8')
    assert '| [Plug](https://github.com/o/plug) |' in text and 'commit ffffffff' in text and 'a/b' in text
    assert '| Tool |' in text and '| OK |' in text


def test_main_logs_failures_and_continues(lib, clean_defender, capsys):
    src, sha = fake_file(lib.tmp, 'good.zip')
    lib.set_catalog([entry('broken', dict(type='url', url='http://example.org/x.zip')),
                     entry('good', dict(type='url', url=src.as_uri(), sha256=sha))])
    fetch.main([])
    out = capsys.readouterr().out
    assert 'FAIL 01_test/broken' in out and 'OK   01_test/good' in out and 'report: 1 entries' in out
