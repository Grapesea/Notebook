"""Run with: python -m unittest discover -s scripts -p 'test_normalize_math.py'."""

import unittest

from normalize_math import normalize_text, unrendered_math_count


class NormalizeMathTests(unittest.TestCase):
    def test_adds_blank_lines_around_display_math(self):
        source = "公式为\n$$\nx+y\n$$\n会回绕.\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, "公式为\n\n$$\nx+y\n$$\n\n会回绕.\n")
        self.assertEqual(warnings, [])
        self.assertEqual(unrendered_math_count(normalized), 0)

    def test_preserves_blockquotes(self):
        source = "> 公式为\n> $$\n> x+y\n> $$\n> 其中\n"
        normalized, _ = normalize_text(source)
        self.assertEqual(normalized, "> 公式为\n>\n> $$\n> x+y\n> $$\n>\n> 其中\n")
        self.assertEqual(unrendered_math_count(normalized), 0)

    def test_ignores_code_fences(self):
        source = "```text\n$$x$$\n$$\n```\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, source)
        self.assertEqual(warnings, [])

    def test_fence_info_inside_blockquote_does_not_close_outer_fence(self):
        source = "> ```c\n> int x;\n> ```\n\n公式为\n$$\nx+y\n$$\n"
        normalized, warnings = normalize_text(source)
        self.assertIn("公式为\n\n$$\nx+y\n$$\n", normalized)
        self.assertEqual(warnings, [])

    def test_converts_embedded_display_delimiters_to_inline(self):
        source = "如果满足：$$x+y$$，则成立.\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, "如果满足：$x+y$，则成立.\n")
        self.assertEqual(warnings, [])

    def test_repairs_repeated_wrappers(self):
        source = "公式为\n\n$$$$x+y$$$$\n\n结束.\n"
        normalized, warnings = normalize_text(source)
        self.assertIn("$$x+y$$", normalized)
        self.assertNotIn("$$$$x+y$$$$", normalized)
        self.assertEqual(warnings, [])

    def test_handles_mixed_delimiter_lines_and_internal_blank(self):
        source = "公式为\n$$\\begin{cases}\nx=1 \\\\\n\ny=2 \\\\\n\\end{cases}$$\n结束.\n"
        normalized, warnings = normalize_text(source)
        self.assertIn("$$\\begin{cases}\nx=1 \\\\\ny=2 \\\\\n\\end{cases}$$\n", normalized)
        self.assertEqual(warnings, [])
        self.assertEqual(unrendered_math_count(normalized), 0)

    def test_does_not_rewrite_adjacent_inline_formulas(self):
        source = "序列：$a$$b$$c$.\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, source)
        self.assertEqual(warnings, [])

    def test_trims_spaces_inside_inline_math(self):
        source = "剩余值$ v$，以及$X_i $，配对$ (c,j)$。\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, "剩余值$v$，以及$X_i$，配对$(c,j)$。\n")
        self.assertEqual(warnings, [])

    def test_repairs_doubled_inline_opener(self):
        source = "其中($$k$ 是给定值)以及`$HOME`。\n"
        normalized, warnings = normalize_text(source)
        self.assertEqual(normalized, "其中($k$ 是给定值)以及`$HOME`。\n")
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
