#!/usr/bin/env python3
"""Resize Chrome Web Store icons from the 1024px source PNG."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from pngutil import place, read_png, resize, write_png

SIZES = (16, 32, 48, 128)
LISTING_SHOTS = (
    ("promo.html", "promo-440x280.png", "440,280"),
    ("screenshot-onboarding.html", "screenshot-onboarding.png", "1280,800"),
    ("screenshot-home.html", "screenshot-home.png", "1280,800"),
    ("screenshot-approve.html", "screenshot-approve.png", "1280,800"),
)


def main() -> None:
    source = ROOT / "store" / "icons" / "icon-source.png"
    public_icon = ROOT / "public" / "icon-128.png"
    if not source.exists():
        if not public_icon.exists():
            raise SystemExit("missing icon source (store/icons/icon-source.png)")
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(public_icon.read_bytes())

    width, height, pixels = read_png(source)
    write_png(source, width, height, pixels)
    print(f"resizing icons from {source.relative_to(ROOT)} ({width}x{height}, {source.stat().st_size} bytes)")

    public = ROOT / "public"
    store_icons = ROOT / "store" / "icons"
    store_icons.mkdir(parents=True, exist_ok=True)

    generated: dict[int, list[int]] = {}
    for size in SIZES:
        generated[size] = resize(pixels, width, height, size, size)
        write_png(public / f"icon-{size}.png", size, size, generated[size])
        write_png(store_icons / f"icon-{size}.png", size, size, generated[size])

    # Store listing icon: 96x96 glyph in a 128x128 canvas with 16px padding.
    padded = [0] * (128 * 128 * 4)
    glyph = resize(pixels, width, height, 96, 96)
    place(padded, 128, 128, glyph, 96, 96, 16, 16)
    write_png(store_icons / "store-icon-128.png", 128, 128, padded)

    print("wrote icons:")
    for size in SIZES:
        path = public / f"icon-{size}.png"
        print(f"  {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")
    listing = store_icons / "store-icon-128.png"
    print(f"  {listing.relative_to(ROOT)} ({listing.stat().st_size} bytes)")
    capture_listing()


def capture_listing() -> None:
    chromium = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser")
    if not chromium:
        print("skip listing screenshots (no chromium)")
        return

    images = ROOT / "store" / "images"
    images.mkdir(parents=True, exist_ok=True)
    listing = ROOT / "store" / "listing"
    cmd_prefix = [chromium, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-sandbox"]
    if not os.environ.get("DISPLAY") and shutil.which("xvfb-run"):
        cmd_prefix = ["xvfb-run", "-a", "--server-args=-screen 0 1280x800x24", *cmd_prefix]

    for html_name, png_name, size in LISTING_SHOTS:
        html = listing / html_name
        out = images / png_name
        subprocess.run(
            [*cmd_prefix, f"--window-size={size}", f"--screenshot={out}", html.as_uri()],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
