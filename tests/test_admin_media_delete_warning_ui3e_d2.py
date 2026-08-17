"""Regression tests for Admin UI v0.3 Phase UI3E-D2 (Delete Dependency Warning).

static/admin.html is a single-file, no-build-step template — these tests
read the file directly and assert on structural markers rather than
exercising a browser, matching the existing lightweight test style for this
file (see test_admin_shell_ui3b.py / test_admin_media_search_filter_ui3e_c.py).
Scoped to the UI3E-D2 delete-preflight addition only.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class MediaDeleteDependencyWarningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()
        cls.delete_fn = cls._extract_function(cls.html, "softDeleteAsset")
        cls.open_blocked_fn = cls._extract_function(cls.html, "openDeleteBlocked")

    @staticmethod
    def _extract_function(html, name):
        match = re.search(
            r"function " + re.escape(name) + r"\([^)]*\) \{(.*?)\n    \}",
            html, re.DOTALL,
        )
        return match.group(1) if match else None

    def test_delete_flow_performs_usage_preflight(self):
        self.assertIsNotNone(self.delete_fn, "softDeleteAsset() body not found")
        self.assertIn("/usage", self.delete_fn)
        self.assertIn("fetch(`/admin/media/assets/${assetId}/usage`", self.delete_fn)

    def test_dependency_modal_and_list_path_exist(self):
        self.assertIn('id="deleteBlockedModal"', self.html)
        self.assertIn('id="db-slugList"', self.html)
        self.assertIsNotNone(self.open_blocked_fn, "openDeleteBlocked() body not found")
        self.assertIn("db-slugList", self.open_blocked_fn)
        self.assertIn("deleteBlockedModal", self.open_blocked_fn)

    def test_slug_list_is_html_escaped(self):
        # Slug values come from the server and are injected via innerHTML —
        # they must go through esc() so a slug can never inject markup.
        self.assertIn("${esc(s)}", self.open_blocked_fn)

    def test_active_usage_blocks_delete_request(self):
        self.assertIn("if (usage.active_usage_count > 0)", self.delete_fn)
        # The DELETE call must appear strictly after the active-usage branch
        # returns, i.e. only reachable when usage is 0.
        branch_pos = self.delete_fn.index("if (usage.active_usage_count > 0)")
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(branch_pos, delete_call_pos)
        self.assertIn("openDeleteBlocked(usage.slugs);", self.delete_fn)

    def test_zero_usage_preserves_existing_delete_path(self):
        self.assertIn("confirm(`Soft-delete asset", self.delete_fn)
        self.assertIn("method: 'DELETE'", self.delete_fn)
        self.assertIn("showMsg('st-msg', 'success', `Asset ${assetId} soft-deleted.`);", self.delete_fn)

    def test_preflight_failure_does_not_proceed_with_deletion(self):
        # Both the !res.ok branch and the catch block must return before any
        # DELETE call is reachable.
        not_ok_pos = self.delete_fn.index("if (!res.ok) {")
        catch_pos = self.delete_fn.index("} catch {\n        showMsg('st-msg', 'error', 'Network error")
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(not_ok_pos, delete_call_pos)
        self.assertLess(catch_pos, delete_call_pos)
        # Every branch ahead of the DELETE call (usage-fetch !ok, usage-fetch
        # network error, active_usage_count > 0, and the user cancelling the
        # confirm()) must return before reaching it.
        preflight_block = self.delete_fn[:delete_call_pos]
        self.assertEqual(preflight_block.count("return;"), 4)

    def test_no_force_delete_or_override_introduced(self):
        # No force/override control or code path was introduced: still exactly
        # one DELETE call site (the original one), and no new function name
        # suggesting a bypass.
        self.assertNotIn("forceDelete", self.html)
        self.assertNotIn("overrideDelete", self.html)
        self.assertEqual(self.delete_fn.count("method: 'DELETE'"), 1)

        # The dependency modal offers only a single close action — no other
        # buttons (e.g. a "continue anyway" control) exist inside it.
        modal_match = re.search(
            r'<div id="deleteBlockedModal".*?</div>\s*</div>\s*</div>', self.html, re.DOTALL
        )
        self.assertIsNotNone(modal_match)
        modal_html = modal_match.group(0)
        self.assertEqual(modal_html.count("<button"), 1)
        self.assertIn('onclick="closeDeleteBlocked()"', modal_html)


if __name__ == "__main__":
    unittest.main()
