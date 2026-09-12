#!/usr/bin/env python3
"""Migrate MkDocs admonition source to Typora/GitHub callout syntax."""

from __future__ import annotations

import argparse
from pathlib import Path

from markdown_callouts import migrate_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path("docs")])
    parser.add_argument("--check", action="store_true", help="report files that need migration without editing")
    args = parser.parse_args()

    files: list[Path] = []
    for path in args.paths:
        files.extend(path.rglob("*.md") if path.is_dir() else [path])

    changed = [path for path in files if path.is_file() and migrate_file(path, check=args.check)]
    for path in changed:
        print(path)
    if args.check and changed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
