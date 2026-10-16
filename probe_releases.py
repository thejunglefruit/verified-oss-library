# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Lists the Windows binaries of the latest release of each repo, to help write the `asset` regex of a
catalog entry (and to see at a glance whether GitHub publishes a SHA256 digest for them).

Usage: python probe_releases.py owner/repo [owner/repo ...]
"""
import json
import re
import subprocess
import sys

NOT_WINDOWS_X64 = re.compile(r'(?i)(arm64|win_arm|aarch|src|source|debug|pdb|\.sha|\.sig|\.asc|symbols|linux|mac|darwin|'
                             r'\.dmg|\.deb|\.rpm|appimage|\.tar)')


def candidates(releases):
    """Latest stable release (or latest at all) and its likely Windows x64 assets."""
    rels = [x for x in releases if not x['draft']]
    stable = [x for x in rels if not x['prerelease']] or rels
    if not stable:
        return None, []
    rel = stable[0]
    return rel, [a for a in rel['assets'] if not NOT_WINDOWS_X64.search(a['name'])]


def main(argv=None):
    repos = sys.argv[1:] if argv is None else argv
    if not repos:
        print(__doc__)
        return 1
    for r in repos:
        p = subprocess.run(['gh', 'api', f'repos/{r}/releases?per_page=5'], capture_output=True, text=True, encoding='utf-8')
        if p.returncode:
            print(f'== {r}: no releases')
            continue
        rel, assets = candidates(json.loads(p.stdout))
        if not rel:
            print(f'== {r}: no releases')
            continue
        print(f"== {r} {rel['tag_name']} {rel['published_at'][:10]}")
        for a in assets[:8]:
            print(f"   {a['name']}  {a['size'] // 1048576}MB  digest={'yes' if a.get('digest') else 'no'}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
