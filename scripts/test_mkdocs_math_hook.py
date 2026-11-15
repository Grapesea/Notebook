"""Run with: python -m unittest discover -s scripts -p 'test_mkdocs_math_hook.py'."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import mkdocs_nav_hook as hook
from mkdocs.config import load_config
from mkdocs.structure.files import get_files
from mkdocs.structure.nav import get_navigation


class MathHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = Path(self.temp.name) / "page.md"
        self.source.write_text("# Page\n\n公式为\n$$\nx+y\n$$\n结束.\n", encoding="utf-8")
        self.page = SimpleNamespace(
            file=SimpleNamespace(abs_src_path=str(self.source), src_uri="page.md")
        )

    def tearDown(self):
        hook._serve_active = False
        self.temp.cleanup()

    def test_build_normalizes_rendered_markdown_without_writing_source(self):
        original = self.source.read_text(encoding="utf-8")
        markdown = hook.on_page_markdown(original, page=self.page, config=None, files=None)
        self.assertIn("公式为\n\n$$\nx+y\n$$\n\n结束.\n", markdown)
        self.assertEqual(self.source.read_text(encoding="utf-8"), original)

    def test_serve_writes_normalized_source(self):
        hook._serve_active = True
        markdown = hook.on_page_markdown(
            self.source.read_text(encoding="utf-8"), page=self.page, config=None, files=None
        )
        self.assertIn("公式为\n\n$$\nx+y\n$$\n\n结束.\n", markdown)
        self.assertIn(
            "公式为\n\n$$\nx+y\n$$\n\n结束.\n",
            self.source.read_text(encoding="utf-8"),
        )

    def test_duplicate_course_pages_use_research_parent(self):
        config_path = Path(__file__).resolve().parents[1] / "mkdocs.yml"
        config = load_config(config_file=str(config_path))
        files = get_files(config)
        nav = get_navigation(files, config)
        hook.on_nav(nav, config=config, files=files)
        for page_path in ("research/cs224n/index.md", "research/cs224w/index.md"):
            page = files.get_file_from_path(page_path).page
            self.assertEqual([item.title for item in page.ancestors], [page_path.split("/")[1].upper(), "科研学习"])


if __name__ == "__main__":
    unittest.main()
