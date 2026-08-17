"""Regression tests for Admin UI v0.3 Phase UI3E-C (Media Asset Search / Filter).

static/admin.html is a single-file, no-build-step template — these tests
read the file directly and assert on structural markers rather than
exercising a browser, matching the existing lightweight test style for this
file (see test_admin_shell_ui3b.py). Scoped to the UI3E-C search/filter
addition only; does not re-verify pre-existing Storage Manager behaviour.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class MediaAssetSearchFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()
        cls.render_fn = cls._extract_function(cls.html, "renderStorageList")
        cls.filter_fn = cls._extract_function(cls.html, "filterStorageList")
        cls.load_fn = cls._extract_function(cls.html, "loadStorage")

    @staticmethod
    def _extract_function(html, name):
        match = re.search(
            r"function " + re.escape(name) + r"\([^)]*\) \{(.*?)\n    \}",
            html, re.DOTALL,
        )
        return match.group(1) if match else None

    @staticmethod
    def _extract_block(text, marker):
        """Return the brace-balanced body of the block starting at `marker`
        (marker must include the opening `{`, e.g. "if (!res.ok) {")."""
        start = text.index(marker)
        brace_start = text.index("{", start)
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_start + 1:i]
        raise AssertionError(f"unbalanced braces while extracting block for marker: {marker!r}")

    def test_search_control_exists(self):
        self.assertIn('id="st-search"', self.html)
        self.assertIn('oninput="filterStorageList()"', self.html)

    def test_media_type_filter_exists_with_expected_options(self):
        self.assertIn('id="st-typeFilter"', self.html)
        self.assertIn('onchange="filterStorageList()"', self.html)
        for value, label in (
            ("all", "All"), ("image", "Image"), ("gif", "GIF"),
            ("video", "Video"), ("audio", "Audio"),
        ):
            self.assertIn(f'<option value="{value}">{label}</option>', self.html)

    def test_client_side_asset_cache_declared(self):
        self.assertIn("let _allAssets = [];", self.html)

    def test_non_ok_response_clears_both_caches(self):
        # UI3E raw-diff repair: a stale-cache bug let _allAssets survive a
        # failed reload while _assetMap (and sometimes _allAssets) leaked
        # into the next render. Every unusable-load branch must clear both.
        self.assertIsNotNone(self.load_fn, "loadStorage() body not found")
        block = self._extract_block(self.load_fn, "if (!res.ok) {")
        self.assertIn("_allAssets = [];", block)
        self.assertIn("_assetMap = {};", block)

    def test_empty_response_clears_both_caches(self):
        self.assertIsNotNone(self.load_fn, "loadStorage() body not found")
        block = self._extract_block(self.load_fn, "if (data.length === 0) {")
        self.assertIn("_allAssets = [];", block)
        self.assertIn("_assetMap = {};", block)

    def test_network_error_catch_clears_both_caches(self):
        self.assertIsNotNone(self.load_fn, "loadStorage() body not found")
        block = self._extract_block(self.load_fn, "} catch {")
        self.assertIn("_allAssets = [];", block)
        self.assertIn("_assetMap = {};", block)

    def test_successful_load_populates_both_caches_and_renders(self):
        self.assertIsNotNone(self.load_fn, "loadStorage() body not found")
        # The success path (after both early-return branches) must still
        # rebuild _assetMap from the response, assign _allAssets = data,
        # and render — this must not regress from the stale-cache fix.
        success_pos = self.load_fn.index("_assetMap = {};\n        data.forEach(a => { _assetMap[a.id] = a; });")
        self.assertIn("_allAssets = data;", self.load_fn[success_pos:])
        self.assertIn("renderStorageList();", self.load_fn[success_pos:])

    def test_render_filters_by_id_name_filename_and_type(self):
        self.assertIsNotNone(self.render_fn, "renderStorageList() body not found")
        self.assertIn("_allAssets.filter(", self.render_fn)
        self.assertIn("a.media_type !== type", self.render_fn)
        self.assertIn("String(a.id)", self.render_fn)
        self.assertIn("a.display_name", self.render_fn)
        self.assertIn("a.original_filename", self.render_fn)

    def test_filter_interaction_renders_locally_without_new_fetch(self):
        self.assertIsNotNone(self.filter_fn, "filterStorageList() body not found")
        self.assertIn("renderStorageList()", self.filter_fn)
        self.assertNotIn("fetch(", self.filter_fn)
        self.assertNotIn("fetch(", self.render_fn)


if __name__ == "__main__":
    unittest.main()
