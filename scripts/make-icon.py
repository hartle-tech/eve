#!/usr/bin/env python3
"""Generate eve's app icon.

The mark is the product's thesis: a square split down the middle, the left
half solid and the right half outlined. What is removed, and what is held
back — given equal area, because the second is why you trust the first.

Dependency-free on purpose: writes the PNG bytes directly so the icon can be
regenerated on any machine with a stock Python, and lives in the repo as a
script rather than as an opaque binary nobody can reproduce.
"""

import struct
import subprocess
import sys
import zlib
from pathlib import Path

SIZE = 1024
OUT = Path(__file__).resolve().parent.parent / "crates" / "eve-app" / "icons"

# Matches --reclaim in the dark UI theme.
TEAL = (0x2E, 0xA3, 0x9E)
INK = (0x14, 0x16, 0x19)
WHITE = (0xFF, 0xFF, 0xFF)


def rounded_square_alpha(x, y, cx, cy, half, radius):
    """Signed coverage of an axis-aligned rounded square, roughly antialiased."""
    dx = abs(x - cx) - (half - radius)
    dy = abs(y - cy) - (half - radius)
    dx = max(dx, 0.0)
    dy = max(dy, 0.0)
    dist = (dx * dx + dy * dy) ** 0.5 - radius
    # One-pixel smoothstep across the boundary.
    return max(0.0, min(1.0, 0.5 - dist))


def build():
    cx = cy = SIZE / 2
    outer_half = SIZE * 0.46
    outer_radius = SIZE * 0.22

    mark_half = SIZE * 0.20
    mark_radius = SIZE * 0.035
    stroke = SIZE * 0.035
    gap = SIZE * 0.018

    rows = []
    for y in range(SIZE):
        row = bytearray()
        row.append(0)  # PNG filter type 0
        for x in range(SIZE):
            bg = rounded_square_alpha(x + 0.5, y + 0.5, cx, cy, outer_half, outer_radius)
            if bg <= 0:
                row += bytes((0, 0, 0, 0))
                continue

            r, g, b = TEAL
            # Subtle vertical lift so the tile does not read as flat fill.
            lift = 1.0 + 0.13 * (1.0 - y / SIZE)
            r, g, b = (min(255, int(c * lift)) for c in (r, g, b))

            outer = rounded_square_alpha(x + 0.5, y + 0.5, cx, cy, mark_half, mark_radius)
            inner = rounded_square_alpha(
                x + 0.5, y + 0.5, cx, cy, mark_half - stroke, mark_radius * 0.6
            )

            left = x + 0.5 < cx - gap / 2
            right = x + 0.5 > cx + gap / 2

            ink = 0.0
            if left:
                # Solid half: everything inside the mark.
                ink = outer
            elif right:
                # Outlined half: the ring only.
                ink = max(0.0, outer - inner)

            if ink > 0:
                r = int(r * (1 - ink) + WHITE[0] * ink)
                g = int(g * (1 - ink) + WHITE[1] * ink)
                b = int(b * (1 - ink) + WHITE[2] * ink)

            row += bytes((r, g, b, int(round(bg * 255))))
        rows.append(bytes(row))

    raw = b"".join(rows)

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    return png


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    png = build()
    master = OUT / "icon.png"
    master.write_bytes(png)
    print(f"wrote {master} ({len(png) // 1024} KB)")

    # Tauri wants a few fixed sizes; sips ships with macOS.
    for size in (32, 128, 256, 512):
        target = OUT / f"{size}x{size}.png"
        subprocess.run(
            ["sips", "-z", str(size), str(size), str(master), "--out", str(target)],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        ["sips", "-z", "256", "256", str(master), "--out", str(OUT / "128x128@2x.png")],
        check=True,
        capture_output=True,
    )
    print(f"wrote {len(list(OUT.glob('*.png')))} icon files")


if __name__ == "__main__":
    sys.exit(main())
