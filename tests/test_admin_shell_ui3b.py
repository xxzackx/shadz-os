"""Regression tests for Admin UI v0.3 Phase UI3B (Admin Shell & Navigation).

static/admin.html is a single-file, no-build-step template — these tests
read the file directly and assert on structural markers rather than
exercising a browser, matching the existing lightweight test style for this
file. Scoped to the shell/navigation addition only; does not re-verify
pre-existing section behaviour covered elsewhere.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminShellNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def test_admin_nav_present_with_expected_links(self):
        nav_match = re.search(
            r'<nav class="admin-nav"[^>]*>(.*?)</nav>', self.html, re.DOTALL
        )
        self.assertIsNotNone(nav_match, "admin-nav shell navigation not found")
        nav_html = nav_match.group(1)

        expected = [
            ("dashboard", "Dashboard"),
            ("slugs", "Slugs"),
            ("media", "Media"),
            ("pages", "Pages"),
            ("bot", "Bot Clients"),
        ]
        for nav_key, label in expected:
            self.assertIn(
                f'data-nav="{nav_key}"', nav_html, f"missing nav link for {nav_key}"
            )
            self.assertIn(label, nav_html, f"missing nav label {label}")

    def test_dashboard_nav_link_defaults_active(self):
        self.assertRegex(
            self.html,
            r'class="nav-link active" data-nav="dashboard"',
            "Dashboard nav link should be active by default on page load",
        )

    def test_module_group_anchors_exist_for_each_nav_target(self):
        for module_id in ("module-slugs", "module-media", "module-pages", "module-bot"):
            self.assertIn(f'id="{module_id}"', self.html)

    def test_existing_section_ids_preserved(self):
        # UI3B must not rename DOM hooks relied on by existing JS/onclick wiring.
        for section_id in (
            "createSection", "updateSection", "statsSection",
            "mediaUploadSection", "attachSection", "storageSection",
            "pageCreateSection", "pageEditSection", "pageAttachSection",
            "botSection",
        ):
            self.assertIn(f'id="{section_id}"', self.html)

    def test_existing_home_card_onclick_hooks_preserved(self):
        for hook in (
            "onclick=\"show('createSection')\"",
            "onclick=\"show('updateSection')\"",
            "onclick=\"show('statsSection')\"",
            "onclick=\"show('mediaUploadSection')\"",
            "onclick=\"show('attachSection')\"",
            "onclick=\"loadStorage(); show('storageSection')\"",
            "onclick=\"show('pageCreateSection')\"",
            "onclick=\"show('pageEditSection')\"",
            "onclick=\"show('pageAttachSection')\"",
            "onclick=\"loadBotClients(); show('botSection')\"",
        ):
            self.assertIn(hook, self.html)

    def test_section_module_map_covers_all_sections(self):
        map_match = re.search(
            r"const SECTION_MODULE = \{(.*?)\};", self.html, re.DOTALL
        )
        self.assertIsNotNone(map_match, "SECTION_MODULE map not found")
        map_body = map_match.group(1)
        for section_id, module_key in (
            ("createSection", "slugs"), ("updateSection", "slugs"), ("statsSection", "slugs"),
            ("mediaUploadSection", "media"), ("attachSection", "media"), ("storageSection", "media"),
            ("pageCreateSection", "pages"), ("pageEditSection", "pages"), ("pageAttachSection", "pages"),
            ("botSection", "bot"),
        ):
            self.assertIn(f"{section_id}: '{module_key}'", map_body)

    def test_show_and_gohome_update_active_nav(self):
        self.assertIn("setActiveNav(SECTION_MODULE[sectionId] || 'dashboard');", self.html)
        self.assertIn("setActiveNav('dashboard');", self.html)

    def test_nav_to_module_reuses_gohome_and_scrolls(self):
        nav_fn_match = re.search(
            r"function navToModule\(moduleKey\) \{(.*?)\}", self.html, re.DOTALL
        )
        self.assertIsNotNone(nav_fn_match)
        body = nav_fn_match.group(1)
        self.assertIn("goHome();", body)
        self.assertIn("setActiveNav(moduleKey);", body)
        self.assertIn("scrollIntoView", body)


if __name__ == "__main__":
    unittest.main()
