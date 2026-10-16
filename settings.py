# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Where things live. Every path can be set three ways, in this order of precedence:

1. an environment variable (OSS_LIBRARY_ROOT, OSS_APPS_DIR, OSS_CATALOG, ...);
2. a JSON file, `config.json` next to these scripts (or the file named by OSS_CONFIG);
3. the default, which is always relative to this folder, so a fresh clone works as is.

Relative paths in the environment or in config.json are resolved against this folder too.
See `config.example.json`.
"""
import json
import os
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent

DEFAULTS = {
    'library_root': 'library',          # downloads, clones, verification.json, REPORT.md
    'apps_dir': 'apps',                 # portable installs and silent installer targets
    'catalogs': None,                   # list; None = catalog.json if present, else catalog.example.json
    'recommendations': 'recommendations.json',   # optional hand-written notes for the per-program README
    'sevenzip': None,                   # None = 7z on PATH, then the standard Program Files location
    'defender': r'C:\Program Files\Windows Defender\MpCmdRun.exe',
}
ENV = {
    'library_root': 'OSS_LIBRARY_ROOT',
    'apps_dir': 'OSS_APPS_DIR',
    'catalogs': 'OSS_CATALOG',          # several files separated by os.pathsep (";" on Windows)
    'recommendations': 'OSS_RECOMMENDATIONS',
    'sevenzip': 'OSS_7Z',
    'defender': 'OSS_DEFENDER',
}


def config_file():
    return Path(os.environ.get('OSS_CONFIG') or HERE / 'config.json')


def _file_config():
    f = config_file()
    if f.exists():
        return json.loads(f.read_text('utf-8'))
    return {}


def get(key):
    env = os.environ.get(ENV[key])
    if env:
        return env
    return _file_config().get(key, DEFAULTS[key])


def resolve(value):
    p = Path(os.path.expandvars(str(value))).expanduser()
    return p if p.is_absolute() else (HERE / p).resolve()


def library_root():
    return resolve(get('library_root'))


def apps_dir():
    return resolve(get('apps_dir'))


def logs_dir():
    return library_root() / '_logs'


def quarantine_dir():
    return library_root() / '_quarantine'


def catalog_files():
    v = get('catalogs')
    if isinstance(v, str):
        v = [x for x in v.split(os.pathsep) if x.strip()]
    if not v:
        v = ['catalog.json'] if (HERE / 'catalog.json').exists() else ['catalog.example.json']
    return [resolve(x) for x in v]


def load_catalog():
    entries = []
    for f in catalog_files():
        entries += json.loads(f.read_text('utf-8'))
    return entries


def recommendations():
    f = resolve(get('recommendations'))
    return json.loads(f.read_text('utf-8')) if f.exists() else {}


def sevenzip():
    v = get('sevenzip')
    if v:
        return Path(v)
    found = shutil.which('7z') or shutil.which('7za')
    if found:
        return Path(found)
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / '7-Zip' / '7z.exe'


def defender():
    return Path(get('defender'))
