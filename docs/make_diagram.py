# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 The Jungle Fruit
"""Draws docs/pipeline.png (the README image) with Pillow: python docs/make_diagram.py"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1600, 860
BG, FG, MUTED = (17, 20, 24), (232, 236, 240), (140, 150, 160)
GREEN, YELLOW, RED, BLUE = (88, 196, 120), (232, 196, 80), (232, 96, 88), (110, 160, 240)


def font(size, bold=False):
    for name in (('consolab.ttf', 'DejaVuSansMono-Bold.ttf') if bold else ('consola.ttf', 'DejaVuSansMono.ttf')):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def box(d, x, y, w, h, title, lines, color):
    d.rounded_rectangle((x, y, x + w, y + h), 14, outline=color, width=3, fill=(26, 30, 36))
    d.text((x + 18, y + 14), title, font=font(26, True), fill=color)
    for i, line in enumerate(lines):
        d.text((x + 18, y + 54 + i * 28), line, font=font(20), fill=FG)


def arrow(d, x1, y1, x2, y2):
    d.line((x1, y1, x2, y2), fill=MUTED, width=3)
    if x2 > x1:
        d.polygon([(x2, y2), (x2 - 14, y2 - 8), (x2 - 14, y2 + 8)], fill=MUTED)
    else:
        d.polygon([(x2, y2), (x2 - 8, y2 - 14), (x2 + 8, y2 - 14)], fill=MUTED)


def main():
    img = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((60, 40), 'verified-oss-library', font=font(44, True), fill=FG)
    d.text((60, 100), 'Nothing reaches your disk as a program until every check has passed.', font=font(24), fill=MUTED)

    bw, bh, y1 = 330, 230, 180
    xs = [60, 440, 820, 1200]
    box(d, xs[0], y1, bw, bh, '1  catalog', ['catalog.json', 'id, category, repo,', 'license, source:', 'gh | winget | url | clone'], BLUE)
    box(d, xs[1], y1, bw, bh, '2  resolve', ['latest GitHub release', 'winget manifest', 'official URL', 'git clone --depth 1'], BLUE)
    box(d, xs[2], y1, bw, bh, '3  download', ['https only', 'urllib, curl fallback', 'old versions removed'], BLUE)
    box(d, xs[3], y1, bw, bh, '4  SHA256', ['vs the official digest', '(GitHub / winget)', 'mismatch -> quarantine', 'none -> YELLOW at best'], YELLOW)
    for a, b in zip(xs, xs[1:]):
        arrow(d, a + bw, y1 + bh // 2, b - 6, y1 + bh // 2)

    y2 = 490
    box(d, xs[3], y2, bw, bh, '5  Defender', ['MpCmdRun custom scan', 'file or whole clone', 'THREAT -> not kept'], YELLOW)
    box(d, xs[2], y2, bw, bh, '6  static scan', ['13 HIGH malware patterns', '4 MEDIUM risk patterns', 'entropy, binaries,', 'domains -> SCAN.md'], YELLOW)
    box(d, xs[1], y2, bw, bh, '7  verdict', ['clean', 'CLEANED (bad files out)', 'REVIEW (entropy only)', 'NOT KEPT -> _quarantine'], RED)
    box(d, xs[0], y2, bw, bh, '8  install', ['zip / 7z portable', 'NSIS /S  Inno /VERYSILENT', 'msi /qn', 'blocked unless verified'], GREEN)
    arrow(d, xs[3] + bw // 2, y1 + bh, xs[3] + bw // 2, y2 - 6)
    for a, b in zip(xs[3:0:-1], xs[2::-1]):
        d.line((a, y2 + bh // 2, b + bw + 6, y2 + bh // 2), fill=MUTED, width=3)
        d.polygon([(b + bw + 2, y2 + bh // 2), (b + bw + 16, y2 + bh // 2 - 8), (b + bw + 16, y2 + bh // 2 + 8)], fill=MUTED)

    d.text((60, 770), 'verification.json + README.md (GREEN / YELLOW / RED) per program  ·  REPORT.md for the whole library',
           font=font(22), fill=MUTED)
    d.text((60, 806), 'long runs: python launch.py chain  (detached)   ·   progress: python status.py', font=font(22), fill=MUTED)
    out = Path(__file__).resolve().parent / 'pipeline.png'
    img.save(out, optimize=True)
    print(out.name)


if __name__ == '__main__':
    main()
