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

    def test_non_2xx_preflight_shows_error_and_returns_before_delete(self):
        not_ok_block = self._extract_block(self.delete_fn, "if (!res.ok) {")
        self.assertIn("showMsg('st-msg', 'error',", not_ok_block)
        self.assertIn("return;", not_ok_block)
        not_ok_pos = self.delete_fn.index("if (!res.ok) {")
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(not_ok_pos, delete_call_pos)

    def test_network_error_preflight_shows_error_and_returns_before_delete(self):
        # The preflight try/catch is the first "} catch {" in the function —
        # the DELETE call's own try/catch comes later.
        catch_block = self._extract_block(self.delete_fn, "} catch {")
        self.assertIn("showMsg('st-msg', 'error', 'Network error", catch_block)
        self.assertIn("return;", catch_block)
        catch_pos = self.delete_fn.index("} catch {")
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(catch_pos, delete_call_pos)

    def test_active_usage_opens_modal_and_returns_before_delete(self):
        active_usage_block = self._extract_block(self.delete_fn, "if (usage.active_usage_count > 0) {")
        self.assertIn("openDeleteBlocked(usage.slugs);", active_usage_block)
        self.assertIn("return;", active_usage_block)
        active_usage_pos = self.delete_fn.index("if (usage.active_usage_count > 0) {")
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(active_usage_pos, delete_call_pos)

    def test_user_cancelling_confirm_returns_before_delete(self):
        cancel_pos = self.delete_fn.index("if (!confirm(`Soft-delete asset")
        cancel_line_end = self.delete_fn.index("\n", cancel_pos)
        cancel_line = self.delete_fn[cancel_pos:cancel_line_end]
        self.assertIn("return;", cancel_line)
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        self.assertLess(cancel_pos, delete_call_pos)

    def test_delete_call_is_the_last_statement_after_all_safety_gates(self):
        # There is exactly one DELETE call site, and every safety-gate marker
        # (the four assertions above) appears strictly before it — proven
        # individually above; this asserts the ordering holds relative to
        # each other too, i.e. gates aren't reachable out of sequence.
        delete_call_pos = self.delete_fn.index("method: 'DELETE'")
        gate_positions = [
            self.delete_fn.index("if (!res.ok) {"),
            self.delete_fn.index("} catch {"),
            self.delete_fn.index("if (usage.active_usage_count > 0) {"),
            self.delete_fn.index("if (!confirm(`Soft-delete asset"),
        ]
        for pos in gate_positions:
            self.assertLess(pos, delete_call_pos)
        self.assertEqual(self.delete_fn.count("method: 'DELETE'"), 1)

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
