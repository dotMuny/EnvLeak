#!/usr/bin/env python3
"""Render docs/demo/envleak.svg: an animated terminal recording of a real run.

The frames are produced by actually executing envleak against a throwaway
repository and capturing its output, so the demo cannot show something the tool
does not do. The result is a self-contained animated SVG rather than a GIF: it
stays crisp at any zoom, weighs a few tens of kilobytes instead of a few
megabytes, renders inline on GitHub, and can be diffed.

The output is not byte-reproducible: the summary line carries the real elapsed
time, which varies between runs. That is why CI does not gate on this file the
way it gates on docs/rules.md — regenerate it when the output format changes,
not on every commit.

Usage:  make demo
"""

from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "envleak"
OUT = ROOT / "docs" / "demo" / "envleak.svg"

COLS, ROWS = 100, 30
CHAR_W, LINE_H = 8.4, 19.0
PAD_X, PAD_Y = 18, 46

# One dark palette; the SVG carries a <style> block that swaps it for a light
# one under prefers-color-scheme, so the demo reads on both GitHub themes.
ANSI = {
    "30": "black", "31": "red", "32": "green", "33": "yellow",
    "34": "blue", "35": "magenta", "36": "cyan", "37": "fg",
    "90": "dim", "91": "red", "92": "green", "93": "yellow",
    "94": "blue", "95": "magenta", "96": "cyan", "97": "fg",
}

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def parse_ansi(line: str):
    """Split a line into (text, class) spans, honouring the SGR codes we emit."""
    spans, pos = [], 0
    classes: list[str] = []
    for m in SGR.finditer(line):
        if m.start() > pos:
            spans.append((line[pos:m.start()], " ".join(classes)))
        codes = [c for c in m.group(1).split(";") if c] or ["0"]
        for code in codes:
            if code == "0":
                classes = []
            elif code == "1":
                classes.append("bold")
            elif code == "2":
                classes.append("dim")
            elif code in ANSI:
                classes = [c for c in classes if c in ("bold", "dim")] + [ANSI[code]]
        pos = m.end()
    if pos < len(line):
        spans.append((line[pos:], " ".join(classes)))
    return spans


def run(cmd: list[str], cwd: Path) -> str:
    env = dict(os.environ, TERM="xterm-256color", NO_COLOR="")
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return (p.stdout + p.stderr).rstrip("\n")


def force_colour(raw: str) -> str:
    """envleak disables colour when stdout is not a tty; re-add it for the demo
    by asking for it explicitly is not possible, so the capture is taken with
    --no-color and the demo colourises the well-known shapes itself."""
    return raw


def build_repo(tmp: Path) -> Path:
    repo = tmp / "acme-api"
    (repo / "src").mkdir(parents=True)
    (repo / "config").mkdir()

    (repo / "src" / "deploy.sh").write_text(
        "#!/bin/sh\n"
        "export AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\n"
        "export AWS_SECRET_ACCESS_KEY=kQ7vTz2mR9dXpL4wNbGs8yJhCe5AuiZr3VoFxMt1\n"
        "aws s3 sync ./dist s3://acme-artifacts\n"
    )
    (repo / "config" / ".env.production").write_text(
        "STRIPE_SECRET_KEY=sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg\n"
        "DATABASE_URL=postgres://app:kR7mQz2XvNb8@db.internal:5432/prod\n"
        "GITHUB_TOKEN=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\n"
    )
    (repo / "README.md").write_text(
        "# acme-api\n\nSet `STRIPE_SECRET_KEY=sk_live_your_key_here` before starting.\n"
    )
    return repo


def frames(repo: Path) -> list[tuple[str, list[str]]]:
    """(prompt, output-lines) pairs, captured from real runs."""
    out = []
    for cmd, argv in [
        ("envleak scan .", [str(BIN), "scan", ".", "--no-color"]),
        ("envleak scan . --format json | jq -r '.rule_id'",
         [str(BIN), "scan", ".", "--format", "json", "--fail-on", "none"]),
    ]:
        raw = run(argv, repo)
        if "jq" in cmd:
            import json
            raw = "\n".join(
                json.loads(l)["rule_id"] for l in raw.splitlines() if l.startswith("{")
            )
        out.append((cmd, raw.splitlines()))
    return out


def colourise(line: str) -> list[tuple[str, str]]:
    """Apply the same colour scheme the real terminal output uses."""
    stripped = line.strip()
    if not stripped:
        return [(line, "")]
    if stripped.startswith("✗"):
        return [(line, "bold red")]
    if stripped.startswith("✓"):
        return [(line, "green")]
    if re.match(r"^\S+$", line) and ("/" in line or "." in line):
        return [(line, "bold cyan")]
    m = re.match(r"^(\s+)(\d+:\d+\s+)(CRITICAL|HIGH|MEDIUM|LOW)(\s+)(\S+)(\s+)(.*)$", line)
    if m:
        sev_class = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}[m.group(3)]
        return [
            (m.group(1), ""), (m.group(2), "dim"), (m.group(3), sev_class),
            (m.group(4), ""), (m.group(5), "blue"), (m.group(6), ""), (m.group(7), "bold"),
        ]
    if line.startswith("  " * 6) or re.match(r"^\s{10,}\S", line):
        return [(line, "dim")]
    return [(line, "")]


def main() -> int:
    if not BIN.exists():
        print(f"{BIN} not found; run `make build` first", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as td:
        repo = build_repo(Path(td))
        captured = frames(repo)

    # Flatten into a single scrolling transcript.
    lines: list[list[tuple[str, str]]] = []
    for prompt, body in captured:
        lines.append([("$ ", "green bold"), (prompt, "bold")])
        for b in body:
            lines.append(colourise(b))
        lines.append([("", "")])

    # Each line appears in turn; the whole transcript then holds and loops.
    per_line = 0.20
    total = per_line * len(lines) + 4.0

    width = int(COLS * CHAR_W) + PAD_X * 2
    height = int(len(lines) * LINE_H) + PAD_Y + PAD_Y // 2

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="13" role="img" aria-label="envleak scanning a repository and reporting four leaked secrets">',
        "<style>",
        ":root{--bg:#11151c;--fg:#c9d1d9;--dim:#6e7781;--red:#ff7b72;--green:#7ee787;"
        "--yellow:#e3b341;--blue:#79c0ff;--cyan:#56d4dd;--magenta:#d2a8ff;--chrome:#1b2129;--border:#30363d}",
        "@media (prefers-color-scheme: light){:root{--bg:#ffffff;--fg:#1f2328;--dim:#818b98;"
        "--red:#cf222e;--green:#1a7f37;--yellow:#9a6700;--blue:#0969da;--cyan:#1b7c83;"
        "--magenta:#8250df;--chrome:#f6f8fa;--border:#d0d7de}}",
        ".t{fill:var(--fg)}.dim{fill:var(--dim)}.red{fill:var(--red)}.green{fill:var(--green)}",
        ".yellow{fill:var(--yellow)}.blue{fill:var(--blue)}.cyan{fill:var(--cyan)}",
        ".magenta{fill:var(--magenta)}.bold{font-weight:700}",
        "@media (prefers-reduced-motion:reduce){.ln{opacity:1!important;animation:none!important}}",
        "</style>",
        f'<rect width="{width}" height="{height}" rx="10" fill="var(--bg)" stroke="var(--border)"/>',
        f'<rect width="{width}" height="34" rx="10" fill="var(--chrome)"/>',
        '<rect y="24" width="%d" height="10" fill="var(--chrome)"/>' % width,
        '<circle cx="20" cy="17" r="5.5" fill="#ff5f56"/>',
        '<circle cx="40" cy="17" r="5.5" fill="#ffbd2e"/>',
        '<circle cx="60" cy="17" r="5.5" fill="#27c93f"/>',
        f'<text x="{width // 2}" y="21" text-anchor="middle" class="dim" font-size="11">envleak</text>',
    ]

    for i, spans in enumerate(lines):
        y = PAD_Y + i * LINE_H
        begin = i * per_line
        parts.append(
            f'<g class="ln" opacity="0">'
            f'<animate attributeName="opacity" values="0;1;1" keyTimes="0;0.02;1" '
            f'dur="{total:.2f}s" begin="{begin:.2f}s" repeatCount="indefinite" fill="freeze"/>'
        )
        x = PAD_X
        for text, cls in spans:
            if not text:
                continue
            classes = "t " + " ".join(c for c in cls.split() if c) if cls else "t"
            parts.append(
                f'<text x="{x:.1f}" y="{y:.1f}" xml:space="preserve" class="{classes}">'
                f"{html.escape(text)}</text>"
            )
            x += len(text) * CHAR_W
        parts.append("</g>")

    parts.append("</svg>")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(parts))
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(lines)} lines, {total:.1f}s loop)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
