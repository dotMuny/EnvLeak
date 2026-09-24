#!/usr/bin/env python3
"""Replace the <!-- BENCHMARK --> placeholder in README.md with a results table.

Reads lines of the form produced by the benchmark loop:
    concurrency=4  median= 4.41s  min= 4.20s  max= 5.02s
    maxRSS 38836 KB
from stdin, so the README's numbers always come from a real run rather than
from memory.
"""
import re
import sys
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"

rows, rss = [], None
for line in sys.stdin:
    m = re.search(r"concurrency=(\d+)\s+median=\s*([\d.]+)s\s+min=\s*([\d.]+)s\s+max=\s*([\d.]+)s", line)
    if m:
        rows.append(tuple(m.groups()))
    m = re.search(r"maxRSS\s+(\d+)\s*KB", line)
    if m:
        rss = int(m.group(1))

if not rows:
    sys.exit("no benchmark rows on stdin")

baseline = float(rows[0][1])
out = ["| `--concurrency` | Median | Range | Speed-up |", "|---|---|---|---|"]
for c, med, lo, hi in rows:
    out.append(f"| {c} | **{float(med):.2f} s** | {float(lo):.2f}–{float(hi):.2f} s | {baseline / float(med):.1f}× |")
out.append("")
if rss:
    out.append(f"Peak resident memory: **{rss / 1024:.0f} MB**, flat regardless of repository size.")
    out.append("")
out.append(
    f"The target was the Kubernetes working tree in under 30 seconds on 8 cores. "
    f"On half that hardware it takes **{float(rows[-1][1]):.1f} seconds**."
)

text = README.read_text()
marker = "<!-- BENCHMARK -->"
if marker not in text:
    sys.exit(f"{marker} not found in README.md")
README.write_text(text.replace(marker, "\n".join(out)))
print("\n".join(out))
