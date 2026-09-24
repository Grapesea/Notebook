"""Convert local raster images to cached WebP files during MkDocs builds.

Source images and Markdown stay untouched. Register this file in ``hooks``.
"""

from __future__ import annotations

import hashlib
import html
from html.parser import HTMLParser
import logging
import os
from pathlib import Path
import posixpath
import re
import tempfile
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from PIL import Image, ImageOps, __version__ as pillow_version


log = logging.getLogger("mkdocs.webp")
EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff"}
QUALITY = 85
_urls: dict[str, str] = {}
_site_path = "/"
_attributes = re.compile(
    r'''(?P<name>[\w:-]+)(?P<equals>\s*=\s*)(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+))'''
)
_css_urls = re.compile(r'''url\(\s*(?P<q>["']?)(?P<url>[^"'()]*?)(?P=q)\s*\)''', re.I)


def convert_image(source: Path, cache: Path) -> tuple[Path, bool]:
    """Cache by file contents and encoder settings, including on coarse-mtime disks."""
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    key = hashlib.sha256(
        f"{digest}:{source.suffix.lower()}:"
        f"{QUALITY}:lossless-png-gif-bmp:v3:{pillow_version}".encode()
    ).hexdigest()
    target = cache / f"{key}.webp"
    if target.is_file():
        return target, True

    cache.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(suffix=".webp", dir=cache)
    os.close(fd)
    try:
        with Image.open(source) as original:
            # MPO JPEGs may contain thumbnails/HDR auxiliaries, not animation frames.
            animated = original.format in {"GIF", "PNG", "WEBP"} and getattr(original, "is_animated", False)
            animation_options = {}
            if animated:
                durations = []
                for frame in range(original.n_frames):
                    original.seek(frame)
                    durations.append(original.info.get("duration", 100))
                original.seek(0)
                animation_options = {"duration": durations, "loop": original.info.get("loop", 0)}
            image = original if animated else ImageOps.exif_transpose(original)
            if not animated and image.mode not in {"RGB", "RGBA"}:
                has_alpha = "A" in image.getbands() or "transparency" in image.info
                image = image.convert("RGBA" if has_alpha else "RGB")
            image.save(
                temporary,
                format="WEBP",
                quality=QUALITY,
                lossless=source.suffix.lower() in {".png", ".gif", ".bmp"},
                method=4,
                save_all=animated,
                icc_profile=original.info.get("icc_profile", b""),
                **animation_options,
            )
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target, False


def rewrite_url(value: str, base: str) -> str:
    """Resolve URLs against an output file; leave external/data URLs intact."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if parts.scheme or parts.netloc or not parts.path:
        return value
    path = unquote(parts.path)
    absolute = path.startswith("/")
    if absolute:
        if not path.startswith(_site_path):
            return value
        key = posixpath.normpath(path[len(_site_path):])
    else:
        key = posixpath.normpath(posixpath.join(posixpath.dirname(base), path))
    target = _urls.get(key)
    if target is None:
        return value
    result = (
        _site_path + target if absolute
        else posixpath.relpath(target, posixpath.dirname(base) or ".")
    )
    return urlunsplit(("", "", quote(result, safe="/"), parts.query, parts.fragment))


def rewrite_css(text: str, base: str) -> str:
    return _css_urls.sub(
        lambda m: f'url({m["q"]}{rewrite_url(m["url"], base)}{m["q"]})', text
    )


def rewrite_srcset(value: str, base: str) -> str:
    # URLs are non-whitespace tokens; commas inside a data URL are not separators.
    def replace(match):
        token = match[0]
        url = token.rstrip(",")
        return rewrite_url(url, base) + token[len(url):]

    return re.sub(r"\S+", replace, value)


class ImageURLs(HTMLParser):
    """Edit attributes only, preserving page markup, scripts and code examples."""

    def __init__(self, base: str):
        super().__init__(convert_charrefs=False)
        self.base = base
        self.output: list[str] = []
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        def replace(match):
            name = match["name"].lower()
            raw = next(v for v in (match["double"], match["single"], match["bare"]) if v is not None)
            value = html.unescape(raw)
            if name in {"src", "href", "poster", "data-src"} or (tag == "meta" and name == "content"):
                changed = rewrite_url(value, self.base)
            elif name == "srcset":
                changed = rewrite_srcset(value, self.base)
            elif name == "style":
                changed = rewrite_css(value, self.base)
            else:
                return match[0]
            if changed == value:
                return match[0]
            return f'{match["name"]}{match["equals"]}"{html.escape(changed, quote=True)}"'

        raw = self.get_starttag_text()
        rewritten = _attributes.sub(replace, raw)
        if rewritten != raw and tag in {"link", "source"}:
            rewritten = re.sub(r'''\btype\s*=\s*(["'])image/(?:png|jpeg|gif|bmp|tiff)\1''',
                               'type="image/webp"', rewritten, flags=re.I)
        self.output.append(rewritten)
        if tag == "style":
            self.in_style = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self.output.append(f"</{tag}>")
        if tag == "style":
            self.in_style = False

    def handle_data(self, data):
        self.output.append(rewrite_css(data, self.base) if self.in_style else data)

    def handle_entityref(self, name):
        self.output.append(f"&{name};")

    def handle_charref(self, name):
        self.output.append(f"&#{name};")

    def handle_comment(self, data):
        self.output.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.output.append(f"<!{decl}>")

    def handle_pi(self, data):
        self.output.append(f"<?{data}>")


def rewrite_html(text: str, base: str) -> str:
    parser = ImageURLs(base)
    parser.feed(text)
    parser.close()
    return "".join(parser.output)


def on_files(files, *, config):
    global _site_path
    _urls.clear()
    _site_path = urlsplit(config.site_url or "/").path.rstrip("/") + "/"
    root = Path(config.config_file_path).resolve().parent
    cache = root / ".cache" / "webp"
    converted = cached = before = after = 0
    occupied = {file.dest_uri for file in files}
    for file in files:
        if Path(file.src_uri).suffix.lower() not in EXTENSIONS or not file.abs_src_path:
            continue
        source = Path(file.abs_src_path)
        old_uri = file.dest_uri
        # Keep the original extension to avoid collisions between foo.jpg and foo.png.
        new_uri = old_uri + ".webp"
        while new_uri in occupied:
            new_uri += ".webp"
        try:
            result, hit = convert_image(source, cache)
        except (OSError, ValueError, RuntimeError, Image.DecompressionBombError) as error:
            log.warning("Keeping original image %s: %s", file.src_uri, error)
            continue
        before += source.stat().st_size
        after += result.stat().st_size
        cached += hit
        converted += not hit
        occupied.add(new_uri)
        _urls[old_uri] = new_uri
        # Retain src_uri so MkDocs can still resolve Markdown references/validate links.
        file.abs_src_path = str(result)
        file.dest_uri = new_uri
        file.__dict__.pop("url", None)
        file.__dict__.pop("abs_dest_path", None)

    for file in files:
        if file.is_css():
            original = file.content_string
            changed = rewrite_css(original, file.dest_uri)
            if changed != original:
                file.content_string = changed
    log.info("WebP: %d converted, %d cached; %.1f MiB -> %.1f MiB",
             converted, cached, before / 1048576, after / 1048576)
    return files


def on_post_page(output, *, page, config):
    return rewrite_html(output, page.file.dest_uri)


def on_post_template(output, *, template_name, config):
    if template_name.endswith((".html", ".htm")):
        return rewrite_html(output, template_name)
    return output
