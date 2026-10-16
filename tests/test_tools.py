# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""settings, readmes, status, launch, analyzer and probe_releases."""
import json
import os

import analyzer
import launch
import probe_releases
import readmes
import settings
import status
from conftest import entry


def test_settings_env_beats_file_beats_default(tmp_path, monkeypatch):
    for var in settings.ENV.values():
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / 'config.json'
    monkeypatch.setenv('OSS_CONFIG', str(cfg))
    assert settings.library_root() == settings.HERE / 'library'
    cfg.write_text(json.dumps({'library_root': 'elsewhere', 'catalogs': ['a.json', 'b.json']}), 'utf-8')
    assert settings.library_root() == settings.HERE / 'elsewhere'
    assert [p.name for p in settings.catalog_files()] == ['a.json', 'b.json']
    monkeypatch.setenv('OSS_LIBRARY_ROOT', str(tmp_path / 'env'))
    monkeypatch.setenv('OSS_CATALOG', os.pathsep.join(['x.json', 'y.json']))
    assert settings.library_root() == tmp_path / 'env'
    assert [p.name for p in settings.catalog_files()] == ['x.json', 'y.json']


def test_example_catalog_is_valid():
    entries = json.loads((settings.HERE / 'catalog.example.json').read_text('utf-8'))
    assert len({e['id'] for e in entries}) == len(entries)
    for e in entries:
        assert {'id', 'name', 'category', 'source'} <= set(e)
        assert e['source']['type'] in ('gh', 'winget', 'url', 'clone')
        if e['source']['type'] == 'url':
            assert e['source']['url'].startswith('https://')


def test_safety_levels():
    assert readmes.safety_level(None)[0] == 'UNVERIFIED'
    assert readmes.safety_level(dict(type='gh', sha256_ok=True, defender='clean'))[0] == 'GREEN'
    assert readmes.safety_level(dict(type='url', sha256_ok=None, defender='clean'))[0] == 'YELLOW'
    assert readmes.safety_level(dict(type='gh', sha256_ok=False))[0] == 'RED'
    clone = dict(type='clone', commit='abc', defender='clean', scanner=dict(high=0, medium=3, files=9, n_binaries=0))
    assert readmes.safety_level(clone)[0] == 'GREEN'
    assert readmes.safety_level(dict(clone, scanner=dict(high=0, n_binaries=2)))[0] == 'YELLOW'


def test_readme_uses_recommendations(lib, monkeypatch):
    e = entry('tool', dict(type='gh'), alternative_to='Something paid')
    folder = lib.root / '01_test' / 'tool'
    folder.mkdir(parents=True)
    (folder / 'verification.json').write_text(json.dumps(dict(type='gh', sha256_ok=True, defender='clean', file='t.zip',
                                                               sha256='ab', version='2.0', date='today')), 'utf-8')
    level = readmes.readme(e, lib.root, {'tool': {'purpose': 'Cuts video.', 'usage': ['Use the portable build.']}}, {})
    text = (folder / 'README.md').read_text('utf-8')
    assert level == 'GREEN' and 'Cuts video.' in text and '- Use the portable build.' in text and '**Replaces:** Something paid' in text


def test_status_counts_done_failed_and_missing(lib, capsys, monkeypatch):
    lib.set_catalog([entry('a', dict(type='gh')), entry('b', dict(type='gh')), entry('c', dict(type='gh'))])
    (lib.root / '01_test' / 'a').mkdir(parents=True)
    (lib.root / '01_test' / 'a' / 'verification.json').write_text('{}', 'utf-8')
    logs = lib.root / '_logs'
    logs.mkdir()
    (logs / '20260101_0000_fetch.log').write_text('OK   01_test/a  v1\nFAIL 01_test/b: no release has an asset\n', 'utf-8')
    monkeypatch.setattr(status, 'processes', lambda: [])
    status.main([])
    out = capsys.readouterr().out
    assert 'catalog: 3  done: 1  failed: 1  pending: 1' in out and '01_test/b: no release' in out
    status.main(['--missing'])
    assert capsys.readouterr().out.strip() == 'c'


def test_launch_commands_pass_args_to_fetch_only():
    cmds = launch.commands('chain', ['--only', 'gimp'])
    names = [[os.path.basename(c[2])] + c[3:] for c in cmds]
    assert names == [['fetch.py', '--only', 'gimp'], ['analyzer.py'], ['readmes.py'], ['fetch.py', '--report']]
    assert launch.commands('update', [])[0][3:] == ['--update']
    assert launch.split_after(['--only', 'x', '--after', '12,34']) == (['--only', 'x'], ['12', '34'])


def test_launch_unknown_task_prints_usage(capsys):
    assert launch.main(['nope']) == 1
    assert 'Usage' in capsys.readouterr().out


def test_analyzer_structure_license_entry_points(tmp_path):
    code = tmp_path / 'code'
    (code / 'src').mkdir(parents=True)
    (code / 'src' / 'main.py').write_text('print(1)\n', 'utf-8')
    (code / 'panel.jsx').write_text('alert(1);\n', 'utf-8')
    (code / 'LICENSE').write_text('MIT License\n\nCopyright ...', 'utf-8')
    (code / 'README.md').write_text('# T\n\n' + 'This tool turns footage into something useful for editors. ' * 2 + '\n', 'utf-8')
    (code / 'package.json').write_text(json.dumps({'name': 't', 'bin': {'t': 'cli.js'}, 'scripts': {'test': 'node t.js'}}), 'utf-8')
    a = analyzer.analyse(code, tmp_path, 'demo', with_semgrep=False)
    assert a['license_detected'] == 'MIT' and a['files'] == 5
    assert a['entry_points']['npm bin'] == {'t': 'cli.js'} and a['entry_points']['scripts at root'] == ['panel.jsx']
    assert 'turns footage' in a['readme']
    assert (tmp_path / 'ANALYSIS.md').read_text('utf-8').startswith('# Code analysis: demo')


def test_probe_picks_windows_assets():
    rels = [dict(draft=False, prerelease=False, tag_name='v1', published_at='2026-01-01T00:00:00Z', assets=[
        dict(name='app-1-win64.zip'), dict(name='app-1-linux.AppImage'), dict(name='app-1.dmg'), dict(name='app-1-win64.zip.sha256')])]
    rel, assets = probe_releases.candidates(rels)
    assert rel['tag_name'] == 'v1' and [a['name'] for a in assets] == ['app-1-win64.zip']
