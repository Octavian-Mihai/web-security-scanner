#!/usr/bin/env python3
"""Render real scanner output as an SVG terminal capture for the README.

usage: render_demo_svg.py "<command shown>" < plain_scan_output.txt > docs/demo.svg
Nothing is invented: the body is exactly the text piped in.
"""

from __future__ import annotations

import html
import sys

COLOURS = {"CRITICAL": "#ff7b72", "HIGH": "#ff7b72", "MEDIUM": "#d29922", "LOW": "#58a6ff"}
LINE_H, PAD, CHAR_W = 20, 18, 8.4


def main() -> None:
    shown = sys.argv[1]
    lines = [("$ " + shown, "#7ee787")] + [(ln, None) for ln in sys.stdin.read().splitlines()]
    width = int(max(len(t) for t, _ in lines) * CHAR_W + PAD * 2)
    height = len(lines) * LINE_H + PAD * 2 + 28
    svg_open = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" '
        'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="14">'
    )
    dots = (
        '<circle cx="20" cy="18" r="6" fill="#ff5f56"/>'
        '<circle cx="40" cy="18" r="6" fill="#ffbd2e"/>'
        '<circle cx="60" cy="18" r="6" fill="#27c93f"/>'
    )
    out = [svg_open, f'<rect width="{width}" height="{height}" rx="8" fill="#0d1117"/>', dots]
    y = 28 + PAD + 10
    for text, colour in lines:
        first = text.split(" ", 1)[0]
        if colour is None and first in COLOURS:
            tag, rest = text[:8], text[8:]
            out.append(f'<text x="{PAD}" y="{y}" xml:space="preserve">'
                       f'<tspan fill="{COLOURS[first]}" font-weight="bold">{html.escape(tag)}'
                       f'</tspan><tspan fill="#e6edf3">{html.escape(rest)}</tspan></text>')
        else:
            fill = colour or ("#8b949e" if text.startswith("         ") else "#e6edf3")
            out.append(f'<text x="{PAD}" y="{y}" fill="{fill}" xml:space="preserve">'
                       f'{html.escape(text)}</text>')
        y += LINE_H
    out.append("</svg>")
    print("\n".join(out))


if __name__ == "__main__":
    main()
