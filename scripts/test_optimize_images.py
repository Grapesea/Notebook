"""Run with: python -m unittest discover -s scripts -p 'test_optimize_images.py'."""

from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from PIL import Image
from mkdocs.structure.files import File, Files
import yaml

import optimize_images as hook


class WebPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        hook._urls.clear()
        hook._site_path = "/Notebook/"

    def tearDown(self):
        self.temp.cleanup()

    def test_lossless_alpha_and_cache_invalidation(self):
        source = self.root / "image.png"
        Image.new("RGBA", (12, 10), (23, 45, 67, 128)).save(source)
        result, hit = hook.convert_image(source, self.root / "cache")
        self.assertFalse(hit)
        with Image.open(result) as image:
            self.assertEqual(image.format, "WEBP")
            self.assertEqual(image.getpixel((0, 0)), (23, 45, 67, 128))
        self.assertEqual(hook.convert_image(source, self.root / "cache"), (result, True))
        Image.new("RGBA", (13, 10), (100, 0, 0, 128)).save(source)
        changed, hit = hook.convert_image(source, self.root / "cache")
        self.assertFalse(hit)
        self.assertNotEqual(result, changed)

    def test_animation_and_orientation(self):
        source = self.root / "animation.gif"
        frames = [Image.new("RGB", (12, 10), color) for color in ("red", "blue")]
        frames[0].save(source, save_all=True, append_images=frames[1:], duration=[100, 200], loop=0)
        result, _ = hook.convert_image(source, self.root / "cache")
        with Image.open(result) as image:
            self.assertEqual(image.n_frames, 2)
            self.assertEqual(image.info["loop"], 0)
            image.seek(0)
            image.load()
            self.assertEqual(image.info["duration"], 100)
            image.seek(1)
            image.load()
            self.assertEqual(image.info["duration"], 200)
        source = self.root / "rotated.jpg"
        exif = Image.Exif()
        exif[274] = 6
        Image.new("RGB", (12, 10), "red").save(source, exif=exif)
        result, _ = hook.convert_image(source, self.root / "cache")
        with Image.open(result) as image:
            self.assertEqual(image.size, (10, 12))

    def test_urls_and_html(self):
        hook._urls["images/a b.png"] = "images/a b.webp"
        text = '''<!DOCTYPE html><img src='../images/a%20b.png?q=1&amp;x=2#crop'>
<img srcset="../images/a%20b.png 1x, https://example.com/a.png 2x">
<link rel="icon" type="image/png" href="/Notebook/images/a%20b.png">
<style>.x { background: url('../images/a%20b.png') }</style>
<script>var example = "../images/a%20b.png";</script>
<code>&lt;img src="../images/a%20b.png"&gt;</code>'''
        output = hook.rewrite_html(text, "notes/page.html")
        self.assertIn('src="../images/a%20b.webp?q=1&amp;x=2#crop"', output)
        self.assertIn('srcset="../images/a%20b.webp 1x, https://example.com/a.png 2x"', output)
        self.assertIn('type="image/webp" href="/Notebook/images/a%20b.webp"', output)
        self.assertIn("url('../images/a%20b.webp')", output)
        self.assertIn('<script>var example = "../images/a%20b.png";</script>', output)
        self.assertIn('<code>&lt;img src="../images/a%20b.png"&gt;</code>', output)
        for url in ("data:image/png;base64,abcd", "https://example.com/a.png", "//example.com/a.png"):
            self.assertEqual(hook.rewrite_url(url, "index.html"), url)

    def test_mpo_jpeg_uses_primary_photo(self):
        source = self.root / "photo.jpg"
        Image.new("RGB", (32, 24), "red").save(
            source, format="MPO", save_all=True,
            append_images=[Image.new("RGB", (16, 12), "blue")],
        )
        result, _ = hook.convert_image(source, self.root / "cache")
        with Image.open(result) as image:
            self.assertEqual(image.size, (32, 24))
            self.assertFalse(image.is_animated)

    def test_same_stem_does_not_overwrite_other_images(self):
        docs = self.root / "docs"
        docs.mkdir()
        names = ["photo.png", "photo.jpg", "photo-png.jpg"]
        for name in names:
            Image.new("RGB", (16, 16), "red").save(docs / name)
        config = SimpleNamespace(site_url=None, config_file_path=str(self.root / "mkdocs.yml"))
        expected = {
            "photo.png": "photo-png-2.webp",
            "photo.jpg": "photo-jpg.webp",
            "photo-png.jpg": "photo-png.webp",
        }
        for order in (names, list(reversed(names))):
            files = Files([File(name, str(docs), str(self.root / "site"), False) for name in order])
            hook.on_files(files, config=config)
            self.assertEqual({file.src_uri: file.dest_uri for file in files}, expected)

    def test_real_build_and_cached_rebuild(self):
        docs = self.root / "docs"
        (docs / "images").mkdir(parents=True)
        (docs / "notes").mkdir()
        for suffix in ("jpg", "png"):
            Image.new("RGB", (32, 32), "red").save(docs / f"images/photo.{suffix}")
        # A pre-existing WebP with the natural destination name must not be overwritten.
        Image.new("RGB", (32, 32), "blue").save(docs / "images/photo.webp")
        Image.new("RGB", (24, 24), "green").save(docs / "images/2.png")
        (docs / "images/broken.png").write_bytes(b"not an image")
        (docs / "index.md").write_text("# Home\n![Photo](images/photo.jpg)\n")
        (docs / "notes/page.md").write_text(
            '# Page\n![Photo](../images/photo.png)\n<img src="../images/photo.jpg">\n'
            '[Download](../images/photo.jpg)\n![Broken](../images/broken.png)\n'
            '![Two](../images/2.png)\n<img src="../images/2.png">\n[Two](../images/2.png)\n'
        )
        (docs / "style.css").write_text('.x {background:url("images/photo.png")}')
        config = {
            "site_name": "Test", "site_url": "https://example.com/Notebook/",
            "use_directory_urls": False, "plugins": [],
            "theme": {"name": "material", "logo": "images/photo.png", "favicon": "images/photo.png", "font": False},
            "hooks": [str(Path(hook.__file__).resolve())], "extra_css": ["style.css"],
        }
        (self.root / "mkdocs.yml").write_text(yaml.safe_dump(config))
        def build(*args):
            result = subprocess.run([sys.executable, "-m", "mkdocs", "build", *args],
                                    cwd=self.root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stderr

        self.assertRegex(build(), r"WebP: \d+ converted, 0 cached")
        site = self.root / "site"
        output = (site / "notes/page.html").read_text()
        self.assertIn('src="../images/photo-png.webp"', output)
        self.assertIn('src="../images/photo-jpg.webp"', output)
        self.assertIn('href="../images/photo-jpg.webp"', output)
        self.assertIn('href="../images/photo-png.webp"', output)
        self.assertEqual(output.count('src="../images/2.webp"'), 2)
        self.assertIn('href="../images/2.webp"', output)
        self.assertTrue((site / "images/2.webp").exists())
        self.assertFalse((site / "images/2.png.webp").exists())
        self.assertEqual((site / "images/photo.webp").read_bytes(), (docs / "images/photo.webp").read_bytes())
        self.assertIn('src="../images/broken.png"', output)
        self.assertFalse((site / "images/photo.jpg").exists())
        self.assertTrue((docs / "images/photo.jpg").exists())
        self.assertIn('images/photo-png.webp', (site / "style.css").read_text())
        self.assertRegex(build("--dirty"), r"WebP: 0 converted, \d+ cached")


if __name__ == "__main__":
    unittest.main()
