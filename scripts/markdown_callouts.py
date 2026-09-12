"""Compatibility helpers for Typora/GitHub-style Markdown callouts."""

from __future__ import annotations

import re
from pathlib import Path


# Map Typora/GitHub/Obsidian names to built-in Material admonition styles.
CALLOUT_STYLES = {
    "note": "note",
    "abstract": "abstract",
    "summary": "abstract",
    "tldr": "abstract",
    "info": "info",
    "todo": "info",
    "tip": "tip",
    "hint": "tip",
    "important": "warning",
    "success": "success",
    "check": "success",
    "done": "success",
    "question": "question",
    "help": "question",
    "faq": "question",
    "warning": "warning",
    "caution": "danger",
    "failure": "failure",
    "fail": "failure",
    "missing": "failure",
    "danger": "danger",
    "error": "danger",
    "bug": "bug",
    "example": "example",
    "quote": "quote",
    "cite": "quote",
}

CALLOUT_MARKER_RE = re.compile(
    r"^(?P<indent>[ ]{0,3})>[ ]*"
    r"\[!(?P<kind>[A-Za-z][\w-]*)\](?P<collapse>[+-])?"
    r"(?P<title>.*)$",
)
QUOTE_LINE_RE = re.compile(r"^(?P<indent>[ ]{0,3})>[ ]?(?P<body>.*)$")
FENCE_RE = re.compile(
    r"^[ ]{0,3}(?:>[ ]?)*[ ]*(?P<fence>`{3,}|~{3,})(?P<rest>.*)$"
)
ADMONITION_RE = re.compile(
    r"^(?P<indent>[ ]{0,3})(?P<marker>!!!|\?\?\?\+?)\s+"
    r"(?P<kind>[A-Za-z][\w-]*)(?:\s+(?P<title>\"(?:[^\"\\]|\\.)*\"))?\s*$"
)


ADMONITION_CALLOUT_TYPES = {
    "note": "NOTE",
    "notes": "NOTE",
    "note1": "NOTE",
    "abstract": "ABSTRACT",
    "summary": "ABSTRACT",
    "tldr": "ABSTRACT",
    "info": "INFO",
    "into": "INFO",
    "todo": "INFO",
    "tip": "TIP",
    "tips": "TIP",
    "hint": "TIP",
    "important": "IMPORTANT",
    "success": "SUCCESS",
    "check": "SUCCESS",
    "done": "SUCCESS",
    "question": "QUESTION",
    "questions": "QUESTION",
    "help": "QUESTION",
    "faq": "QUESTION",
    "warning": "WARNING",
    "caution": "CAUTION",
    "failure": "FAILURE",
    "fail": "FAILURE",
    "missing": "FAILURE",
    "danger": "CAUTION",
    "error": "CAUTION",
    "bug": "BUG",
    "example": "EXAMPLE",
    "quote": "QUOTE",
    "cite": "QUOTE",
}


def convert_callouts(markdown: str) -> str:
    """Convert quote callouts to admonition syntax without editing source files."""
    trailing_newline = markdown.endswith(("\n", "\r"))
    lines = markdown.splitlines()
    output: list[str] = []
    fence_character = ""
    fence_length = 0
    index = 0
    while index < len(lines):
        line = lines[index]
        fence_match = FENCE_RE.match(line)
        if fence_character:
            output.append(line)
            if fence_match:
                fence = fence_match.group("fence")
                if (
                    fence[0] == fence_character
                    and len(fence) >= fence_length
                    and not fence_match.group("rest").strip()
                ):
                    fence_character = ""
                    fence_length = 0
            index += 1
            continue
        if fence_match:
            fence = fence_match.group("fence")
            fence_character = fence[0]
            fence_length = len(fence)
            output.append(line)
            index += 1
            continue

        marker = CALLOUT_MARKER_RE.match(line)
        if marker is None:
            output.append(line)
            index += 1
            continue

        indent = marker.group("indent")
        kind = marker.group("kind")
        style = CALLOUT_STYLES.get(kind.casefold(), "note")
        title = marker.group("title").strip()
        if not title:
            title = kind.replace("-", " ").replace("_", " ").title()
        title = title.replace("\\", "\\\\").replace('"', '\\"')
        collapse = marker.group("collapse")
        directive = "???+" if collapse == "+" else "???" if collapse == "-" else "!!!"
        output.append(f'{indent}{directive} {style} "{title}"')

        index += 1
        body: list[str] = []
        while index < len(lines):
            quote = QUOTE_LINE_RE.match(lines[index])
            if quote is None or quote.group("indent") != indent:
                break
            body.append(quote.group("body"))
            index += 1

        # Recursion supports nested callouts while the fence handling prevents
        # markers shown inside code examples from being converted.
        converted_body = convert_callouts("\n".join(body)).splitlines()
        output.extend(f"{indent}    {body_line}" for body_line in converted_body)

    result = "\n".join(output)
    if trailing_newline:
        result += "\n"
    return result


def _unquote_title(value: str | None) -> str:
    if not value:
        return ""
    return value[1:-1].replace(r'\"', '"').replace(r"\\", "\\")


def migrate_admonitions(markdown: str) -> str:
    """Convert standard MkDocs admonitions to Typora/GitHub callout blocks."""
    trailing_newline = markdown.endswith(("\n", "\r"))
    lines = markdown.splitlines()
    output: list[str] = []
    fence_character = ""
    fence_length = 0
    index = 0

    while index < len(lines):
        line = lines[index]
        fence_match = FENCE_RE.match(line)
        if fence_character:
            output.append(line)
            if fence_match:
                fence = fence_match.group("fence")
                if (
                    fence[0] == fence_character
                    and len(fence) >= fence_length
                    and not fence_match.group("rest").strip()
                ):
                    fence_character = ""
                    fence_length = 0
            index += 1
            continue
        if fence_match:
            fence = fence_match.group("fence")
            fence_character = fence[0]
            fence_length = len(fence)
            output.append(line)
            index += 1
            continue

        admonition = ADMONITION_RE.match(line)
        callout_type = (
            ADMONITION_CALLOUT_TYPES.get(admonition.group("kind").casefold())
            if admonition
            else None
        )
        if not admonition or not callout_type:
            output.append(line)
            index += 1
            continue

        indent = admonition.group("indent")
        marker = admonition.group("marker")
        suffix = "+" if marker == "???+" else "-" if marker == "???" else ""
        title = _unquote_title(admonition.group("title"))
        header = f"{indent}> [!{callout_type}]{suffix}"
        if title:
            header += f" {title}"
        output.append(header)

        content_indent = len(indent) + 4
        index += 1
        body: list[str] = []
        while index < len(lines):
            candidate = lines[index]
            if not candidate.strip():
                following = index + 1
                while following < len(lines) and not lines[following].strip():
                    following += 1
                if following >= len(lines) or len(lines[following]) - len(lines[following].lstrip(" ")) < content_indent:
                    break
                body.append("")
                index += 1
                continue
            leading = len(candidate) - len(candidate.lstrip(" "))
            if leading < content_indent:
                break
            body.append(candidate[content_indent:])
            index += 1

        # Nested admonitions are migrated before quote prefixes are restored.
        converted_body = migrate_admonitions("\n".join(body)).splitlines()
        output.extend(f"{indent}> {body_line}" if body_line else f"{indent}>" for body_line in converted_body)

    result = "\n".join(output)
    if trailing_newline:
        result += "\n"
    return result


def migrate_file(path: Path, *, check: bool = False) -> bool:
    """Migrate one Markdown file, preserving its original newline convention."""
    raw = path.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8-sig")
    normalized = text.replace("\r\n", "\n")
    migrated = migrate_admonitions(normalized)
    output = migrated.replace("\n", newline).encode("utf-8")
    if output == raw:
        return False
    if not check:
        path.write_bytes(output)
    return True
