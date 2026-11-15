#!/usr/bin/env python3
"""Check and normalize display-math delimiters in MkDocs Markdown files."""

from __future__ import annotations

import argparse
import re
from html.parser import HTMLParser
from pathlib import Path

from markdown import markdown
from pymdownx.arithmatex import ArithmatexExtension


FENCE_RE = re.compile(r"^(?P<prefix>\s*(?:>\s*)*)(?P<fence>`{3,}|~{3,})")
LIST_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<marker>[-+*]|\d+[.)])\s+")
QUOTE_PREFIX_RE = re.compile(r"^\s*(?:>\s*)+")
INLINE_CODE_RE = re.compile(r"(?P<ticks>`+).+?(?P=ticks)")


def split_quote_prefix(line: str) -> tuple[str, str]:
    """Split blockquote markers from the Markdown content that follows."""
    match = QUOTE_PREFIX_RE.match(line)
    if not match:
        return "", line
    return line[: match.end()], line[match.end() :]


def blank_for(line: str) -> str:
    """Create a blank line that stays inside the same blockquote depth."""
    prefix, _ = split_quote_prefix(line)
    return prefix.rstrip() if prefix else ""


def is_blank_container(line: str) -> bool:
    _, body = split_quote_prefix(line)
    return not body.strip()


def fence_state(line: str, fence: str | None) -> str | None:
    """Return the active code-fence marker after processing one line."""
    _, body = split_quote_prefix(line)
    match = re.match(r"^\s*(`{3,}|~{3,})(?P<info>.*)$", body)
    if not match:
        return fence
    marker = match.group(1)
    if fence is None:
        return marker
    if marker[0] == fence[0] and len(marker) >= len(fence) and not match.group("info").strip():
        return None
    return fence


def in_list_context(lines: list[str], index: int) -> bool:
    """Return whether a display block is indented as list-item content."""
    _, body = split_quote_prefix(lines[index])
    content_indent = len(body) - len(body.lstrip(" \t"))
    if content_indent == 0:
        return False

    for previous in reversed(lines[max(0, index - 40) : index]):
        if not previous.strip():
            continue
        _, previous_body = split_quote_prefix(previous)
        match = LIST_ITEM_RE.match(previous_body)
        if match:
            item_indent = len(match.group("indent").expandtabs(4))
            return item_indent < content_indent
    return False


def normalize_inline_math(body: str) -> str:
    """Trim spaces just inside single-dollar inline math delimiters."""
    # Dollar signs inside inline code are literal and must not participate in
    # delimiter pairing. Mask them while preserving offsets.
    masked = INLINE_CODE_RE.sub(lambda match: match.group().replace("$", "\0"), body)
    runs = [(match.start(), len(match.group())) for match in re.finditer(r"\$+", masked)]
    singles = [start for start, length in runs if length == 1]
    replacements: list[tuple[int, int, str]] = []
    for opener, closer in zip(singles[::2], singles[1::2]):
        inner = body[opener + 1 : closer]
        trimmed = inner.strip()
        if trimmed and trimmed != inner:
            replacements.append((opener + 1, closer, trimmed))
    for start, end, replacement in reversed(replacements):
        body = body[:start] + replacement + body[end:]

    # A frequent OCR typo is ``($$x$``: a doubled opener followed by a normal
    # closer. Keep this narrowly scoped so real display-math syntax is untouched.
    return re.sub(r"\(\$\$([^$\n]+)\$(?=[\s),.;，。])", r"($\1$", body)


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Apply safe delimiter fixes and return warnings for manual review."""
    # Keep trailing empty elements so formatting does not add or remove EOF
    # newlines in files that do not contain formulas.
    lines = text.split("\n")
    warnings: list[str] = []
    fence: str | None = None

    for index, line in enumerate(lines):
        previous_fence = fence
        fence = fence_state(line, fence)
        if previous_fence is not None or fence is not None or FENCE_RE.match(line):
            continue

        quote_prefix, body = split_quote_prefix(line)
        body = normalize_inline_math(body)
        lines[index] = quote_prefix + body
        stripped = body.strip()

        # OCR/import tools sometimes double the display wrapper. Normalize the
        # common $$$...$$$ and $$$$...$$$$ forms before parsing pairs.
        for wrapper in ("$$$$", "$$$"):
            if stripped.startswith(wrapper) and stripped.endswith(wrapper):
                inner = stripped[len(wrapper) : -len(wrapper)].strip()
                if inner:
                    lines[index] = f"{quote_prefix}{wrapper[:2]}{inner}{wrapper[:2]}"
                    body = split_quote_prefix(lines[index])[1]
                    stripped = body.strip()
                break

        # An embedded single-line display expression is almost always a
        # mistaken inline delimiter. Converting it preserves sentence flow and
        # prevents literal '$' characters around the rendered formula.
        occurrences = [position for position in range(len(body) - 1) if body[position : position + 2] == "$$"]
        if len(occurrences) == 2:
            first, second = occurrences
            before = body[:first]
            after = body[second + 2 :]
            # Adjacent inline formulas such as ``$a$$b$`` also contain two
            # runs of '$$'. An odd number of remaining single '$' characters
            # means the run is an inline-formula boundary, not a display pair.
            inline_boundary = before.count("$") % 2 or after.count("$") % 2
            if (before.strip() or after.strip()) and not inline_boundary:
                line_indent = len(body) - len(body.lstrip(" \t"))
                safe_context = bool(quote_prefix) or line_indent < 4 or in_list_context(lines, index)
                if safe_context:
                    body = body[:first] + "$" + body[first + 2 : second] + "$" + body[second + 2 :]
                    lines[index] = quote_prefix + body

        if re.search(r"\${3,}", stripped):
            warnings.append(f"line {index + 1}: unexpected run of three or more '$' characters")

    blocks: list[tuple[int, int]] = []
    opener: int | None = None
    fence = None
    for index, line in enumerate(lines):
        previous_fence = fence
        fence = fence_state(line, fence)
        if previous_fence is not None or fence is not None or FENCE_RE.match(line):
            continue
        _, body = split_quote_prefix(line)
        stripped = body.strip()
        if opener is None:
            if not stripped.startswith("$$"):
                continue
            if stripped.endswith("$$") and stripped.count("$$") >= 2:
                blocks.append((index, index))
            else:
                opener = index
        elif stripped.endswith("$$"):
            blocks.append((opener, index))
            opener = None
    if opener is not None:
        warnings.append(f"line {opener + 1}: display-math opener has no closing '$$'")

    blocks.sort()
    output: list[str] = []
    cursor = 0
    for start, end in blocks:
        if start < cursor:
            continue
        output.extend(lines[cursor:start])
        block_lines = lines[start : end + 1]
        if start != end:
            block_lines = [
                block_line
                for offset, block_line in enumerate(block_lines)
                if offset in {0, len(block_lines) - 1} or not is_blank_container(block_line)
            ]
        opening = block_lines[0]
        closing = block_lines[-1]
        if output and not is_blank_container(output[-1]):
            output.append(blank_for(opening))
        output.extend(block_lines)
        cursor = end + 1
        if cursor < len(lines) and not is_blank_container(lines[cursor]):
            output.append(blank_for(closing))

    output.extend(lines[cursor:])
    return "\n".join(output), warnings


class UnrenderedMathParser(HTMLParser):
    """Find literal '$$' text outside code and rendered arithmatex nodes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.unrendered = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.stack.append((tag, {key: value or "" for key, value in attrs}))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if "$$" not in data:
            return
        if any(tag in {"pre", "code", "script", "style"} for tag, _ in self.stack):
            return
        if any("arithmatex" in attrs.get("class", "") for _, attrs in self.stack):
            return
        self.unrendered += data.count("$$")


def unrendered_math_count(text: str) -> int:
    rendered = markdown(text, extensions=[ArithmatexExtension(generic=True)])
    parser = UnrenderedMathParser()
    parser.feed(rendered)
    return parser.unrendered


def normalize_file(path: Path, *, check: bool = False) -> tuple[bool, list[str], int]:
    raw = path.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    original = raw.decode("utf-8-sig").replace("\r\n", "\n")
    normalized, warnings = normalize_text(original)
    changed = normalized != original
    unrendered = unrendered_math_count(normalized)
    if changed and not check:
        path.write_bytes(normalized.replace("\n", newline).encode("utf-8"))
    return changed, warnings, unrendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path("docs")])
    parser.add_argument("--check", action="store_true", help="report files without modifying them")
    args = parser.parse_args()

    files = [
        file
        for path in args.paths
        for file in (path.rglob("*.md") if path.is_dir() else [path])
    ]
    failed = False
    for path in files:
        if not path.is_file():
            continue
        changed, warnings, unrendered = normalize_file(path, check=args.check)
        if changed:
            if args.check:
                failed = True
                print(f"{path}: needs formatting")
            else:
                print(f"{path}: formatted")
        for warning in warnings:
            failed = True
            print(f"{path}: {warning}")
        if unrendered:
            failed = True
            print(f"{path}: {unrendered} literal '$$' token(s) remain unrendered")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
