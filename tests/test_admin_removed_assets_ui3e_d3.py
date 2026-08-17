"""Regression tests for Admin UI v0.3 Phase UI3E-D3 (Removed Assets Page).

static/admin.html is a single-file, no-build-step template — these tests
read the file directly and assert on structural markers rather than
exercising a browser, matching the existing lightweight test style for this
file (see test_admin_media_search_filter_ui3e_c.py). Scoped to the UI3E-D3
Removed Assets sub-view addition only; does not re-verify pre-existing
Storage Manager (UI3E-C) or delete-preflight (UI3E-D2) behaviour beyond
confirming they remain untouched.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class RemovedAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()
        cls.load_fn = cls._extract_function(cls.html, "loadRemovedAssets")
        cls.render_fn = cls._extract_function(cls.html, "renderRemovedList")
        cls.filter_fn = cls._extract_function(cls.html, "filterRemovedList")
        cls.card_fn = cls._extract_function(cls.html, "buildRemovedAssetCard")
        cls.toggle_fn = cls._extract_function(cls.html, "showStorageView")

        # Pre-existing UI3E-C / UI3E-D2 functions, used for regression checks only.
        cls.active_load_fn = cls._extract_function(cls.html, "loadStorage")
        cls.active_render_fn = cls._extract_function(cls.html, "renderStorageList")
        cls.set_active_nav_fn = cls._extract_function(cls.html, "setActiveNav")
        cls.soft_delete_fn = cls._extract_function(cls.html, "softDeleteAsset")

    @staticmethod
    def _extract_function(html, name):
        match = re.search(
            r"function " + re.escape(name) + r"\([^)]*\) \{(.*?)\n    \}",
            html, re.DOTALL,
        )
        return match.group(1) if match else None

    # ── View toggle ──────────────────────────────────────────────────────

    def test_removed_assets_view_control_exists(self):
        self.assertIn('id="st-tab-active"', self.html)
        self.assertIn('id="st-tab-removed"', self.html)
        self.assertIn("onclick=\"showStorageView('active')\"", self.html)
        self.assertIn("onclick=\"showStorageView('removed')\"", self.html)
        self.assertIn('id="st-activeView"', self.html)
        self.assertIn('id="st-removedView"', self.html)

    # ── Data loading ─────────────────────────────────────────────────────

    def test_removed_assets_load_uses_include_deleted_true(self):
        self.assertIsNotNone(self.load_fn, "loadRemovedAssets() body not found")
        self.assertIn("/admin/media/assets?include_deleted=true", self.load_fn)

    def test_only_is_deleted_true_records_are_rendered(self):
        self.assertIn("data.filter(a => a.is_deleted === true)", self.load_fn)

    # ── Card content ─────────────────────────────────────────────────────

    def test_removed_card_displays_storage_key(self):
        self.assertIsNotNone(self.card_fn, "buildRemovedAssetCard() body not found")
        self.assertIn("R2 Object Key", self.card_fn)
        self.assertIn("a.storage_key", self.card_fn)

    def test_removed_card_displays_deleted_at(self):
        self.assertIn("Removed At", self.card_fn)
        self.assertIn("a.deleted_at", self.card_fn)

    def test_removed_card_has_no_active_asset_actions(self):
        for forbidden in ("attachAssetToSlug(", "softDeleteAsset(", "renameAsset("):
            self.assertNotIn(forbidden, self.card_fn)
        for forbidden_label in ("Attach", "Restore", "Replace"):
            self.assertNotIn(forbidden_label, self.card_fn)

    # ── Search / filter ──────────────────────────────────────────────────

    def test_removed_search_control_exists(self):
        self.assertIn('id="rm-search"', self.html)
        self.assertIn('oninput="filterRemovedList()"', self.html)

    def test_removed_type_filter_has_expected_options(self):
        self.assertIn('id="rm-typeFilter"', self.html)
        self.assertIn('onchange="filterRemovedList()"', self.html)
        # UI3E-C already asserts the shared option markup exists once for
        # st-typeFilter; here we only need a second instance for rm-typeFilter.
        self.assertEqual(self.html.count('<option value="all">All</option>'), 2)
        self.assertEqual(self.html.count('<option value="image">Image</option>'), 2)
        self.assertEqual(self.html.count('<option value="gif">GIF</option>'), 2)
        self.assertEqual(self.html.count('<option value="video">Video</option>'), 2)
        self.assertEqual(self.html.count('<option value="audio">Audio</option>'), 2)

    def test_removed_search_covers_id_name_filename_and_storage_key(self):
        self.assertIsNotNone(self.render_fn, "renderRemovedList() body not found")
        self.assertIn("_removedAssets.filter(", self.render_fn)
        self.assertIn("a.media_type !== type", self.render_fn)
        self.assertIn("String(a.id)", self.render_fn)
        self.assertIn("a.display_name", self.render_fn)
        self.assertIn("a.original_filename", self.render_fn)
        self.assertIn("a.storage_key", self.render_fn)

    def test_filter_interaction_is_client_side_with_no_extra_fetch(self):
        self.assertIsNotNone(self.filter_fn, "filterRemovedList() body not found")
        self.assertIn("renderRemovedList()", self.filter_fn)
        self.assertNotIn("fetch(", self.filter_fn)
        self.assertNotIn("fetch(", self.render_fn)

    # ── UI3E-C regression protection ────────────────────────────────────

    def test_active_storage_manager_search_filter_unaffected(self):
        self.assertIsNotNone(self.active_load_fn, "loadStorage() body not found")
        self.assertIsNotNone(self.active_render_fn, "renderStorageList() body not found")
        self.assertIn("_allAssets = data;", self.active_load_fn)
        self.assertIn("_allAssets.filter(", self.active_render_fn)
        # The active list load must never pass include_deleted, so removed
        # records can never leak into the active Storage Manager view.
        self.assertNotIn("include_deleted", self.active_load_fn)

    # ── Sub-tab / global-nav isolation ───────────────────────────────────

    def test_subtabs_use_isolated_class_not_global_nav_link(self):
        # setActiveNav() does document.querySelectorAll('.nav-link') and clears
        # .active on anything not matching data-nav — the D3 sub-tabs must use
        # a separate class so that global nav sweep can never touch them.
        self.assertIsNotNone(self.set_active_nav_fn, "setActiveNav() body not found")
        self.assertIn("querySelectorAll('.nav-link')", self.set_active_nav_fn)
        self.assertIn('class="subtab-link active" id="st-tab-active"', self.html)
        self.assertIn('class="subtab-link" id="st-tab-removed"', self.html)
        self.assertNotIn('class="nav-link active" id="st-tab-active"', self.html)
        self.assertNotIn('class="nav-link" id="st-tab-removed"', self.html)

    # ── Cache freshness after soft-delete ───────────────────────────────

    def test_successful_soft_delete_invalidates_removed_assets_cache(self):
        self.assertIsNotNone(self.soft_delete_fn, "softDeleteAsset() body not found")
        success_pos = self.soft_delete_fn.index("showMsg('st-msg', 'success',")
        invalidate_pos = self.soft_delete_fn.index("_removedAssetsLoaded = false;")
        self.assertGreater(invalidate_pos, success_pos)


if __name__ == "__main__":
    unittest.main()
