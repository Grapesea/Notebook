#!/usr/bin/env python3
"""Keep the leaf pages in mkdocs.yml in sync with docs/.

The file is edited line-by-line on purpose: loading and dumping the whole YAML
document would also reformat unrelated settings and comments.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable

from pathspec import GitIgnoreSpec


MANAGED_MARKER = "mkdocs-nav-sync"
MARKER_COMMENT = f"  # {MANAGED_MARKER}"
LEAF_RE = re.compile(
    r"^(?P<indent>\s*)-\s+(?P<label>.+):\s+"
    r"(?P<path>(?:\"[^\"]+\.md\"|'[^']+\.md'|[^\s#]+\.md))"
    r"(?P<tail>\s*(?:#.*)?)$"
)
BARE_LEAF_RE = re.compile(
    r"^(?P<indent>\s*)-\s+"
    r"(?P<path>(?:\"[^\"]+\.md\"|'[^']+\.md'|[^\s#]+\.md))"
    r"(?P<tail>\s*(?:#.*)?)$"
)
GROUP_RE = re.compile(r"^(?P<indent>\s*)-\s+(?P<label>.+?):\s*(?P<tail>#.*)?$")
FRONT_MATTER_TITLE_RE = re.compile(r"^title\s*:\s*(.+?)\s*$", re.IGNORECASE)
H1_RE = re.compile(r"^#\s+(.+?)\s*#*\s*$")


def yaml_string(value: str) -> str:
    """JSON strings are valid YAML and avoid scalar edge cases."""
    return json.dumps(value, ensure_ascii=False)


def unquote_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, str) else value
        except json.JSONDecodeError:
            return value[1:-1]
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    return value


def clean_heading(value: str) -> str:
    value = re.sub(r"!\[([^]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"[*_`~]", "", value)
    value = re.sub(r"\s+\{[^}]*\}\s*$", "", value)
    return value.strip()


def page_title(path: Path, relative_path: str) -> str:
    """Read a useful nav title without requiring every note to have metadata."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        lines = []

    if lines and lines[0].strip() == "---":
        for line in lines[1:]:
            if line.strip() == "---":
                break
            match = FRONT_MATTER_TITLE_RE.match(line)
            if match:
                title = unquote_yaml_scalar(match.group(1))
                if title:
                    return clean_heading(title)

    in_fence = False
    fence = ""
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            token = stripped[:3]
            if not in_fence:
                in_fence, fence = True, token
            elif token == fence:
                in_fence = False
            continue
        if not in_fence:
            match = H1_RE.match(line)
            if match:
                title = clean_heading(match.group(1))
                if title:
                    return title

    pure = PurePosixPath(relative_path)
    stem = pure.stem
    if stem.casefold() == "index" and pure.parent.name:
        stem = pure.parent.name
    return stem.replace("_", " ").strip() or "Untitled"


@dataclass
class Container:
    """A YAML sequence: nav itself, or the children of a group item."""

    item_indent: int
    parent: "Container | None" = None
    group_line: int | None = None
    managed: bool = False
    children: list["Leaf | Container"] = field(default_factory=list)
    end_line: int = 0

    def leaves(self) -> list["Leaf"]:
        result: list[Leaf] = []
        for child in self.children:
            if isinstance(child, Leaf):
                result.append(child)
            else:
                result.extend(child.leaves())
        return result


@dataclass
class Leaf:
    line: int
    indent: int
    label: str
    path: str
    tail: str
    parent: Container
    bare: bool = False

    @property
    def managed(self) -> bool:
        return MANAGED_MARKER in self.tail


@dataclass
class ParsedNav:
    lines: list[str]
    newline: str
    root: Container
    nav_start: int
    nav_end: int

    @property
    def leaves(self) -> list[Leaf]:
        return self.root.leaves()


def parse_nav(raw: bytes) -> ParsedNav:
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8-sig")
    lines = text.splitlines()

    try:
        nav_start = next(i for i, line in enumerate(lines) if line.strip() == "nav:" and not line[:1].isspace())
    except StopIteration as exc:
        raise ValueError("mkdocs config does not contain a top-level 'nav:' section") from exc

    nav_end = len(lines)
    for index in range(nav_start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.startswith("#"):
            nav_end = index
            break

    root = Container(item_indent=2, end_line=nav_end)
    stack: list[Container] = [root]

    for index in range(nav_start + 1, nav_end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        leaf_match = LEAF_RE.match(line)
        bare_match = None if leaf_match else BARE_LEAF_RE.match(line)
        group_match = None if leaf_match or bare_match else GROUP_RE.match(line)
        match = leaf_match or bare_match or group_match
        if not match:
            continue

        indent = len(match.group("indent").expandtabs(2))
        while len(stack) > 1 and indent < stack[-1].item_indent:
            stack[-1].end_line = index
            stack.pop()

        if indent != stack[-1].item_indent:
            # Do not guess how to modify an unconventional nav fragment.
            continue

        if leaf_match or bare_match:
            path = unquote_yaml_scalar(match.group("path"))
            label = unquote_yaml_scalar(leaf_match.group("label")) if leaf_match else PurePosixPath(path).stem
            stack[-1].children.append(
                Leaf(
                    line=index,
                    indent=indent,
                    label=label,
                    path=path.replace("\\", "/"),
                    tail=match.group("tail") or "",
                    parent=stack[-1],
                    bare=bool(bare_match),
                )
            )
            continue

        child_container = Container(
            item_indent=indent + 2,
            parent=stack[-1],
            group_line=index,
            managed=MANAGED_MARKER in (group_match.group("tail") or ""),
            end_line=nav_end,
        )
        stack[-1].children.append(child_container)
        stack.append(child_container)

    while len(stack) > 1:
        stack[-1].end_line = nav_end
        stack.pop()
    root.end_line = nav_end
    return ParsedNav(lines, newline, root, nav_start, nav_end)


def load_ignore_spec(path: Path) -> GitIgnoreSpec:
    if not path.exists():
        return GitIgnoreSpec.from_lines([])
    return GitIgnoreSpec.from_lines(path.read_text(encoding="utf-8-sig").splitlines())


def markdown_files(docs_dir: Path, ignore_path: Path) -> dict[str, Path]:
    spec = load_ignore_spec(ignore_path)
    result: dict[str, Path] = {}
    for path in docs_dir.rglob("*"):
        # Check the suffix before stat'ing the path; docs/ can contain many
        # large image trees that are irrelevant to navigation.
        if path.suffix.casefold() != ".md" or not path.is_file():
            continue
        relative = path.relative_to(docs_dir).as_posix()
        if not spec.match_file(relative):
            result[relative] = path
    return result


def normalized_stem(path: str) -> str:
    return re.sub(r"[\W_]+", "", PurePosixPath(path).stem, flags=re.UNICODE).casefold()


def pair_obvious_renames(stale: Iterable[str], missing: Iterable[str]) -> dict[str, str]:
    """Pair only unambiguous punctuation/case-only renames in the same folder."""
    stale_groups: dict[tuple[PurePosixPath, str], list[str]] = defaultdict(list)
    new_groups: dict[tuple[PurePosixPath, str], list[str]] = defaultdict(list)
    for value in stale:
        pure = PurePosixPath(value)
        stale_groups[(pure.parent, normalized_stem(value))].append(value)
    for value in missing:
        pure = PurePosixPath(value)
        new_groups[(pure.parent, normalized_stem(value))].append(value)

    result: dict[str, str] = {}
    for key, old_values in stale_groups.items():
        new_values = new_groups.get(key, [])
        if len(old_values) == len(new_values) == 1:
            result[old_values[0]] = new_values[0]
    return result


def container_depth(container: Container) -> int:
    depth = 0
    while container.parent is not None:
        depth += 1
        container = container.parent
    return depth


def common_parent(container: Container, live_paths: set[str]) -> PurePosixPath | None:
    parents = [PurePosixPath(leaf.path).parent for leaf in container.leaves() if leaf.path in live_paths]
    if not parents:
        return None
    common = list(parents[0].parts)
    for parent in parents[1:]:
        while common and tuple(parent.parts[: len(common)]) != tuple(common):
            common.pop()
    return PurePosixPath(*common) if common else PurePosixPath(".")


def choose_container(root: Container, target_dir: PurePosixPath, live_paths: set[str]) -> tuple[Container, PurePosixPath]:
    containers: list[Container] = []

    def collect(container: Container) -> None:
        containers.append(container)
        for child in container.children:
            if isinstance(child, Container):
                collect(child)

    collect(root)

    exact: list[Container] = []
    for container in containers:
        if any(PurePosixPath(leaf.path).parent == target_dir and leaf.path in live_paths for leaf in container.children if isinstance(leaf, Leaf)):
            exact.append(container)
    if exact:
        selected = max(exact, key=container_depth)
        return selected, target_dir

    inferred: list[tuple[int, int, Container, PurePosixPath]] = []
    for container in containers:
        base = common_parent(container, live_paths)
        if base is None:
            continue
        base_parts = () if str(base) == "." else base.parts
        if base_parts and target_dir.parts[: len(base_parts)] == base_parts:
            inferred.append((len(base_parts), container_depth(container), container, base))
    if inferred:
        _, _, selected, base = max(inferred, key=lambda item: (item[0], item[1]))
        return selected, base
    return root, PurePosixPath(".")


def render_leaf(indent: int, title: str, relative_path: str) -> str:
    return f"{' ' * indent}- {yaml_string(title)}: {yaml_string(relative_path)}{MARKER_COMMENT}"


def render_new_tree(indent: int, base: PurePosixPath, paths: list[str], docs: dict[str, Path]) -> list[str]:
    """Render paths below base as nested, deterministic groups."""
    tree: dict[str, object] = {}
    base_parts = () if str(base) == "." else base.parts
    for relative in sorted(paths, key=str.casefold):
        pure = PurePosixPath(relative)
        rest = pure.parts[len(base_parts) :]
        cursor = tree
        for directory in rest[:-1]:
            cursor = cursor.setdefault(directory, {})  # type: ignore[assignment]
        cursor.setdefault("__files__", []).append(relative)  # type: ignore[union-attr]

    output: list[str] = []

    def emit(node: dict[str, object], level: int) -> None:
        for relative in node.get("__files__", []):  # type: ignore[union-attr]
            output.append(render_leaf(level, page_title(docs[relative], relative), relative))
        for name, child in node.items():
            if name == "__files__":
                continue
            output.append(f"{' ' * level}- {yaml_string(name)}:{MARKER_COMMENT}")
            emit(child, level + 2)  # type: ignore[arg-type]

    emit(tree, indent)
    return output


def replace_leaf_line(leaf: Leaf, title: str, path: str, managed: bool | None = None) -> str:
    if managed is None:
        managed = leaf.managed
    marker = MARKER_COMMENT if managed else (leaf.tail if leaf.tail else "")
    return f"{' ' * leaf.indent}- {yaml_string(title)}: {yaml_string(path)}{marker}"


def sync(config_path: Path, docs_dir: Path, ignore_path: Path, explicit_renames: dict[str, str] | None = None, check: bool = False) -> bool:
    raw = config_path.read_bytes()
    parsed = parse_nav(raw)
    docs = markdown_files(docs_dir, ignore_path)
    live_paths = set(docs)
    explicit_renames = {
        PurePosixPath(old).as_posix(): PurePosixPath(new).as_posix()
        for old, new in (explicit_renames or {}).items()
        if new in live_paths
    }

    nav_paths = {leaf.path for leaf in parsed.leaves}
    stale_paths = nav_paths - live_paths
    missing_paths = live_paths - nav_paths
    renames = dict(explicit_renames)
    renames.update({
        old: new
        for old, new in pair_obvious_renames(stale_paths - renames.keys(), missing_paths - set(renames.values())).items()
    })

    replacements: dict[int, str] = {}
    deletions: set[int] = set()
    effective_paths: set[str] = set()

    for leaf in parsed.leaves:
        new_path = renames.get(leaf.path, leaf.path)
        if new_path not in live_paths:
            deletions.add(leaf.line)
            continue
        effective_paths.add(new_path)
        if new_path != leaf.path:
            title = page_title(docs[new_path], new_path) if leaf.managed else leaf.label
            replacements[leaf.line] = replace_leaf_line(leaf, title, new_path)
        elif leaf.managed:
            title = page_title(docs[new_path], new_path)
            replacements[leaf.line] = replace_leaf_line(leaf, title, new_path, managed=True)

    missing = sorted(live_paths - effective_paths, key=str.casefold)
    additions: dict[int, list[str]] = defaultdict(list)
    by_target: dict[tuple[int, PurePosixPath], list[str]] = defaultdict(list)
    containers_by_id: dict[int, Container] = {}
    for relative in missing:
        target_dir = PurePosixPath(relative).parent
        container, base = choose_container(parsed.root, target_dir, live_paths)
        key = (id(container), base)
        containers_by_id[id(container)] = container
        by_target[key].append(relative)

    pending_additions: dict[int, list[tuple[int, list[str]]]] = defaultdict(list)
    containers_with_additions: set[int] = set()
    for (container_id, base), paths in by_target.items():
        container = containers_by_id[container_id]
        containers_with_additions.add(container_id)
        rendered = render_new_tree(container.item_indent, base, paths, docs)
        pending_additions[container.end_line].append((container_depth(container), rendered))
    for line, batches in pending_additions.items():
        # Several nested sequences can end at the same source line. Their new
        # items must be emitted from deepest to shallowest to remain siblings.
        for _, rendered in sorted(batches, key=lambda item: item[0], reverse=True):
            additions[line].extend(rendered)

    # Remove generated groups that have no surviving leaves. Manual groups are kept.
    def prune_generated(container: Container) -> bool:
        has_live_leaf = False
        for child in container.children:
            if isinstance(child, Leaf):
                if child.line not in deletions:
                    has_live_leaf = True
            elif prune_generated(child):
                has_live_leaf = True
        has_additions = id(container) in containers_with_additions
        if container.managed and not has_live_leaf and not has_additions and container.group_line is not None:
            deletions.add(container.group_line)
            return False
        return has_live_leaf or has_additions

    prune_generated(parsed.root)

    output: list[str] = []
    for index, line in enumerate(parsed.lines):
        if index in additions:
            output.extend(additions[index])
        if index not in deletions:
            output.append(replacements.get(index, line))
    if len(parsed.lines) in additions:
        output.extend(additions[len(parsed.lines)])

    new_text = parsed.newline.join(output)
    if raw.endswith((b"\n", b"\r")):
        new_text += parsed.newline
    new_raw = new_text.encode("utf-8")
    if new_raw == raw.lstrip(b"\xef\xbb\xbf"):
        return False
    if check:
        return True

    config_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{config_path.name}.", dir=config_path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(new_raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, stat.S_IMODE(config_path.stat().st_mode))
        os.replace(temporary_name, config_path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return True


def relative_event_path(path: str, docs_dir: Path) -> str | None:
    try:
        return Path(path).resolve().relative_to(docs_dir.resolve()).as_posix()
    except ValueError:
        return None


def watch(config_path: Path, docs_dir: Path, ignore_path: Path) -> None:
    try:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers.polling import PollingObserver
    except ImportError as exc:
        raise SystemExit("watch mode requires watchdog; run: pip install -r requirements.txt") from exc

    class Handler(FileSystemEventHandler):
        def __init__(self) -> None:
            self.lock = threading.Lock()
            self.timer: threading.Timer | None = None
            self.renames: dict[str, str] = {}

        def on_any_event(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            source = relative_event_path(event.src_path, docs_dir)
            destination_path = getattr(event, "dest_path", "")
            destination = relative_event_path(destination_path, docs_dir) if destination_path else None
            ignore_changed = Path(event.src_path).resolve() == ignore_path.resolve()
            markdown_changed = (source and source.casefold().endswith(".md")) or (destination and destination.casefold().endswith(".md"))
            if not ignore_changed and not markdown_changed:
                return
            with self.lock:
                if source and destination and source.casefold().endswith(".md") and destination.casefold().endswith(".md"):
                    self.renames[source] = destination
                if self.timer:
                    self.timer.cancel()
                self.timer = threading.Timer(0.5, self.run_sync)
                self.timer.daemon = True
                self.timer.start()

        def run_sync(self) -> None:
            with self.lock:
                renames, self.renames = self.renames, {}
            try:
                changed = sync(config_path, docs_dir, ignore_path, renames)
                if changed:
                    print("[mkdocs-nav] updated mkdocs.yml", flush=True)
            except Exception as exc:  # keep watching after a malformed intermediate save
                print(f"[mkdocs-nav] sync failed: {exc}", file=sys.stderr, flush=True)

    changed = sync(config_path, docs_dir, ignore_path)
    print(f"[mkdocs-nav] {'updated' if changed else 'checked'} {config_path.name}; watching {docs_dir}", flush=True)
    observer = PollingObserver(timeout=1.0)
    handler = Handler()
    observer.schedule(handler, str(docs_dir), recursive=True)
    observer.schedule(handler, str(ignore_path.parent), recursive=False)
    observer.start()
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
        observer.join()


def build_parser() -> argparse.ArgumentParser:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=repository / "mkdocs.yml")
    parser.add_argument("--docs", type=Path, default=repository / "docs")
    parser.add_argument("--ignore", type=Path, default=repository / ".mkdocsignore")
    parser.add_argument("--watch", action="store_true", help="keep running and sync after Markdown saves")
    parser.add_argument("--check", action="store_true", help="exit 1 when mkdocs.yml needs synchronization")
    parser.add_argument("--rename", nargs=2, metavar=("OLD", "NEW"), action="append", default=[], help="preserve a renamed page's position; paths are relative to docs/")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config_path = args.config.resolve()
    docs_dir = args.docs.resolve()
    ignore_path = args.ignore.resolve()
    if args.watch:
        if args.check or args.rename:
            raise SystemExit("--watch cannot be combined with --check or --rename")
        watch(config_path, docs_dir, ignore_path)
        return 0
    changed = sync(config_path, docs_dir, ignore_path, dict(args.rename), check=args.check)
    if args.check and changed:
        print("mkdocs.yml is not synchronized", file=sys.stderr)
        return 1
    print("updated mkdocs.yml" if changed else "mkdocs.yml is already synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
