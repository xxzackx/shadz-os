"""Regression tests for Admin UI v0.3 Phase UI3C (Dashboard Home / System Overview).

static/admin.html is a single-file, no-build-step template — these tests
read the file directly and assert on structural markers rather than
exercising a browser, matching the existing lightweight test style for this
file. Scoped to the System Overview addition only; does not re-verify
pre-existing shell/navigation behaviour covered by test_admin_shell_ui3b.py.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminDashboardOverviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def test_system_overview_group_exists(self):
        self.assertIn('id="module-overview"', self.html)
        self.assertIn("System Overview", self.html)

    def test_link_engine_card_navigates_to_slugs(self):
        self.assertIn("onclick=\"navToModule('slugs')\"", self.html)

    def test_media_engine_card_navigates_to_media(self):
        self.assertIn("onclick=\"navToModule('media')\"", self.html)

    def test_page_engine_card_navigates_to_pages(self):
        self.assertIn("onclick=\"navToModule('pages')\"", self.html)

    def test_bot_clients_card_navigates_to_bot(self):
        self.assertIn("onclick=\"navToModule('bot')\"", self.html)

    def test_media_and_bot_overview_dom_ids_exist(self):
        for dom_id in ("ov-media-value", "ov-media-hint", "ov-bot-value", "ov-bot-hint"):
            self.assertIn(f'id="{dom_id}"', self.html)

    def test_overview_loader_functions_exist(self):
        for fn_name in ("loadDashboardOverview", "loadMediaOverview", "loadBotOverview"):
            self.assertRegex(self.html, rf"function {fn_name}\(")

    def test_media_overview_uses_media_assets_endpoint(self):
        fn_match = re.search(
            r"function loadMediaOverview\(\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(fn_match, "loadMediaOverview function body not found")
        self.assertIn("/admin/media/assets", fn_match.group(1))

    def test_bot_overview_uses_bot_clients_endpoint(self):
        fn_match = re.search(
            r"function loadBotOverview\(\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(fn_match, "loadBotOverview function body not found")
        self.assertIn("/admin/bot/clients", fn_match.group(1))

    def test_dashboard_overview_registered_on_dom_content_loaded(self):
        self.assertIn(
            "document.addEventListener('DOMContentLoaded', loadDashboardOverview);",
            self.html,
        )

    def test_mobile_overview_breakpoint_is_one_column(self):
        media_match = re.search(
            r"@media \(max-width: 480px\) \{\s*\.overview-grid \{([^}]*)\}",
            self.html,
        )
        self.assertIsNotNone(media_match, "mobile .overview-grid breakpoint not found")
        self.assertIn("grid-template-columns: 1fr;", media_match.group(1))


if __name__ == "__main__":
    unittest.main()
