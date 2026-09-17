#!/usr/bin/env python3
"""Zip dist/ into a Chrome Web Store upload with manifest.json at the root."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
STORE = ROOT / "store"

SKIP_SUFFIXES = {".map", ".svg"}
SKIP_NAMES = {".DS_Store", "LICENSE.txt", "package.json", ".gitignore"}

REQUIRED = (
    "manifest.json",
    "background.js",
    "content.js",
    "inpage.js",
    "popup.html",
    "popup.js",
    "icon-16.png",
    "icon-32.png",
    "icon-48.png",
    "icon-128.png",
)


def collect_files() -> list[Path]:
    if not DIST.is_dir():
        raise SystemExit("dist/ is missing; run npm run build first")

    files: list[Path] = []
    for path in sorted(DIST.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES:
            continue
        files.append(path)
    return files


def validate(files: list[Path], manifest: dict) -> None:
    names = {path.relative_to(DIST).as_posix() for path in files}
    missing = [name for name in REQUIRED if name not in names]
    if missing:
        raise SystemExit(f"store package is missing: {', '.join(missing)}")

    wasm = [name for name in names if name.endswith(".wasm")]
    if not wasm:
        raise SystemExit("store package is missing the wallet WASM module")

    popup_html = (DIST / "popup.html").read_text()
    if 'src="/' in popup_html or 'href="/' in popup_html:
        raise SystemExit("popup.html must use relative asset paths for Chrome extension pages")

    csp = manifest.get("content_security_policy", {}).get("extension_pages", "")
    if "wasm-unsafe-eval" not in csp:
        raise SystemExit("manifest CSP must allow wasm-unsafe-eval")

    icons = manifest.get("icons", {})
    if "128" not in icons:
        raise SystemExit("manifest must declare a 128px PNG icon")
    for size, icon in icons.items():
        if not str(icon).endswith(".png"):
            raise SystemExit(f"Chrome Web Store icons must be PNG (icons[{size}]={icon})")
        if icon not in names:
            raise SystemExit(f"manifest icon {icon} is not in the package")


def main() -> None:
    files = collect_files()
    manifest = json.loads((DIST / "manifest.json").read_text())
    validate(files, manifest)

    version = manifest["version"]
    STORE.mkdir(parents=True, exist_ok=True)
    zip_path = STORE / f"nunchi-wallet-{version}.zip"
    if zip_path.exists():
        zip_path.unlink()

    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(DIST).as_posix())

    names = [path.relative_to(DIST).as_posix() for path in files]
    print(f"wrote {zip_path} ({zip_path.stat().st_size} bytes, {len(names)} files)")
    for name in names:
        print(f"  {name}")


if __name__ == "__main__":
    main()
