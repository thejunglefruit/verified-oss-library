# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""install.py without running any real installer: portable zips, refusals and installer detection."""
import json
import zipfile

import install
from conftest import entry


def verified(lib, id_, file_name, **v):
    folder = lib.root / '01_test' / id_
    folder.mkdir(parents=True, exist_ok=True)
    data = dict(id=id_, file=file_name, version='1.0', defender='clean', sha256_ok=True, verdict='clean')
    data.update(v)
    (folder / 'verification.json').write_text(json.dumps(data), 'utf-8')
    return folder


def test_portable_zip_is_extracted_and_flattened(lib):
    folder = verified(lib, 'tool', 'tool.zip')
    with zipfile.ZipFile(folder / 'tool.zip', 'w') as z:
        z.writestr('tool-1.0/tool.exe', b'MZ')
        z.writestr('tool-1.0/unins000.exe', b'MZ')
        z.writestr('tool-1.0/data/readme.txt', 'hi')
    r = install.install(entry('tool', dict(type='gh')))
    assert r['status'] == 'portable extracted'
    assert (lib.apps / 'tool' / 'tool.exe').exists() and r['executables'] == ['tool.exe']
    install.register([r])
    assert 'tool.exe' in (lib.apps / 'INSTALLED.md').read_text('utf-8')


def test_zip_slip_is_refused(lib):
    folder = verified(lib, 'evil', 'evil.zip')
    with zipfile.ZipFile(folder / 'evil.zip', 'w') as z:
        z.writestr('../escape.txt', 'x')
    r = install.install(entry('evil', dict(type='gh')))
    assert r['status'].startswith('ERROR: unsafe path')
    assert not (lib.apps / 'escape.txt').exists()


def test_failed_verification_is_never_installed(lib):
    verified(lib, 'bad', 'bad.zip', sha256_ok=False)
    verified(lib, 'threat', 'threat.zip', defender='THREAT: x')
    assert install.install(entry('bad', dict(type='gh')))['status'].startswith('BLOCKED')
    assert install.install(entry('threat', dict(type='gh')))['status'].startswith('BLOCKED')
    assert install.install(entry('never', dict(type='gh')))['status'].startswith('no installer')
    assert not lib.apps.exists()


def test_installer_kind(tmp_path):
    cases = {'inno': b'..Inno Setup..', 'nsis': b'..Nullsoft..', 'squirrel': b'..Squirrel..', 'unknown': b'MZ'}
    for kind, data in cases.items():
        p = tmp_path / f'{kind}.exe'
        p.write_bytes(data)
        assert install.installer_kind(p) == kind
