"""Project hooks for navigation sync and Markdown rendering compatibility."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from markdown_callouts import convert_callouts
from normalize_math import normalize_file, normalize_text
from sync_mkdocs_nav import parse_nav, sync


log = logging.getLogger("mkdocs.nav-sync")
_serve_active = False

# These pages intentionally appear in both CSDIY and Research. MkDocs assigns
# their parent from the last occurrence, so pin the canonical navigation branch.
_PREFERRED_NAV_PARENTS = {
    "research/cs224n/index.md": "CS224N",
    "research/cs224w/index.md": "CS224W",
}


def on_startup(*, command: str, dirty: bool) -> None:
    """Enable synchronization only for the long-running development server."""
    del dirty
    global _serve_active
    _serve_active = command == "serve"
    if _serve_active:
        log.info("Navigation synchronization is enabled")


def _read_synced_nav(config_path: Path) -> list[object]:
    parsed = parse_nav(config_path.read_bytes())
    nav_yaml = parsed.newline.join(parsed.lines[parsed.nav_start : parsed.nav_end])
    value = yaml.safe_load(nav_yaml)
    return value["nav"]


def on_config(config):
    """Synchronize before every live-reload build and use it immediately."""
    if not _serve_active or not config.config_file_path:
        return config

    config_path = Path(config.config_file_path).resolve()
    ignore_path = config_path.parent / ".mkdocsignore"
    changed = sync(config_path, Path(config.docs_dir), ignore_path)
    if changed:
        # The config object was loaded just before this hook ran. Update its
        # in-memory nav too, so the current build does not need to wait for the
        # follow-up reload caused by writing mkdocs.yml.
        config["nav"] = _read_synced_nav(config_path)
        log.info("Updated %s", config_path.name)
    return config


def on_serve(server, *, config, builder):
    """Rebuild when the ignore rules change as well as when docs change."""
    del builder
    if config.config_file_path:
        ignore_path = Path(config.config_file_path).resolve().parent / ".mkdocsignore"
        server.watch(str(ignore_path))
    return server


def on_nav(nav, *, config, files):
    """Keep intentionally duplicated course pages under their canonical section."""
    del config, files
    sections = {}

    def collect(items):
        for item in items:
            if item.is_section:
                sections.setdefault(item.title, item)
                collect(item.children)

    collect(nav.items)
    for page in nav.pages:
        section_title = _PREFERRED_NAV_PARENTS.get(page.file.src_uri)
        section = sections.get(section_title)
        if section is not None and page.parent is not section:
            page.parent = section
            log.info("Pinned %s to %s", page.file.src_uri, section_title)
    return nav


def on_page_markdown(markdown: str, *, page, config, files) -> str:
    """Normalize formula delimiters and render Typora/GitHub callouts."""
    del config, files
    normalized, warnings = normalize_text(markdown)

    source_path = getattr(page.file, "abs_src_path", None)
    if _serve_active and source_path:
        changed, file_warnings, unrendered = normalize_file(Path(source_path))
        warnings.extend(file_warnings)
        if changed:
            log.info("Normalized math formatting in %s", page.file.src_uri)
        if unrendered:
            warnings.append(f"{unrendered} literal '$$' token(s) remain unrendered")

    for warning in dict.fromkeys(warnings):
        log.warning("%s: %s", page.file.src_uri, warning)

    markdown = normalized
    return convert_callouts(markdown)


def on_shutdown() -> None:
    global _serve_active
    _serve_active = False
