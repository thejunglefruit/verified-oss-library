# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Shared fixtures. No test touches the network: downloads are file:// URLs to local fake files,
Defender and git are replaced with monkeypatch, and every path points into a temporary folder."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def lib(tmp_path, monkeypatch):
    """An empty library, apps folder and catalog in tmp_path, wired through the environment."""
    root, apps = tmp_path / 'library', tmp_path / 'apps'
    catalog = tmp_path / 'catalog.json'
    catalog.write_text('[]', 'utf-8')
    monkeypatch.setenv('OSS_CONFIG', str(tmp_path / 'no-config.json'))
    monkeypatch.setenv('OSS_LIBRARY_ROOT', str(root))
    monkeypatch.setenv('OSS_APPS_DIR', str(apps))
    monkeypatch.setenv('OSS_CATALOG', str(catalog))
    monkeypatch.setenv('OSS_RECOMMENDATIONS', str(tmp_path / 'no-recs.json'))
    monkeypatch.setenv('OSS_7Z', str(tmp_path / 'no-7z.exe'))   # force the standard-library zip path

    class Lib:
        pass
    lb = Lib()
    lb.root, lb.apps, lb.catalog, lb.tmp = root, apps, catalog, tmp_path

    def set_catalog(entries):
        catalog.write_text(json.dumps(entries), 'utf-8')
    lb.set_catalog = set_catalog
    return lb


def entry(id_, source, category='01_test', **kw):
    e = dict(id=id_, name=id_.title(), category=category, repo=None, license='MIT', notes='', source=source)
    e.update(kw)
    return e
