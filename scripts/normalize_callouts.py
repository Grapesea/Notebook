#!/usr/bin/env python3
"""Normalize Markdown callouts to Typora's five supported types."""

from __future__ import annotations

import argparse
from pathlib import Path

from markdown_callouts import normalize_callouts


def normalize_file(path: Path, *, check: bool = False) -> bool:
    raw = path.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8-sig")
    normalized = normalize_callouts(text.replace("\r\n", "\n"))
    output = normalized.replace("\n", newline).encode("utf-8")
    if output == raw:
        return False
    if not check:
        path.write_bytes(output)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path("docs")])
    parser.add_argument("--check", action="store_true", help="report files needing normalization")
    args = parser.parse_args()
    files = [file for path in args.paths for file in (path.rglob("*.md") if path.is_dir() else [path])]
    changed = [file for file in files if file.is_file() and normalize_file(file, check=args.check)]
    print(*(str(file) for file in changed), sep="\n")
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
