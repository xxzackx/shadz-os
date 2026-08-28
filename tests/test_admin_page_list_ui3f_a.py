"""Lightweight structural regression tests for the Admin UI v0.3 Phase UI3F-A
Page List / Browse view added to static/admin.html.

static/admin.html is a single-file, no-build-step template — these tests read
the file directly and assert on structural markers, matching the existing
lightweight style of test_admin_shell_ui3b.py / test_admin_dashboard_ui3c.py.
Scoped to the UI3F-A browse addition; existing Page Create/Edit/Attach markers
are checked only to confirm they were not removed.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminPageListUI3FATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def test_page_list_section_and_dom_hooks_exist(self):
        for marker in (
            'id="pageListSection"',
            'id="pageList"',
            'id="pl-search"',
            'id="pl-templateFilter"',
            'id="pl-statusFilter"',
        ):
            self.assertIn(marker, self.html)

    def test_page_list_home_card_loads_and_shows_section(self):
        self.assertIn("loadPageList(); show('pageListSection')", self.html)

    def test_page_list_js_functions_exist(self):
        for fn_name in ("loadPageList", "renderPageList", "filterPageList", "buildPageCard"):
            self.assertRegex(self.html, rf"function {fn_name}\(")

    def test_page_list_uses_new_read_endpoint(self):
        fn_match = re.search(
            r"async function loadPageList\(\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(fn_match, "loadPageList function body not found")
        self.assertIn("/admin/pages", fn_match.group(1))

    def test_page_list_registered_in_section_module_map(self):
        self.assertIn("pageListSection: 'pages'", self.html)

    def test_filters_are_client_side_only_no_refetch_in_render(self):
        fn_match = re.search(
            r"function renderPageList\(\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(fn_match, "renderPageList function body not found")
        self.assertNotIn("fetch(", fn_match.group(1))

    def test_existing_page_sections_preserved(self):
        for marker in (
            'id="pageCreateSection"',
            'id="pageEditSection"',
            'id="pageAttachSection"',
            "function createPage(",
            "function editPage(",
            "function attachPage(",
            "function detachPage(",
            "function attachPageInline(",
            "function detachPageInline(",
        ):
            self.assertIn(marker, self.html)

    def test_no_mutation_controls_added_in_browse_view(self):
        section = re.search(
            r'<div id="pageListSection".*?</div>\s*\n\s*<!-- Telegram Bot Clients section -->',
            self.html,
            re.DOTALL,
        )
        self.assertIsNotNone(section, "pageListSection block not found")
        body = section.group(0)
        # browse-only: no edit/archive/attach/detach/preview affordances this phase
        for forbidden in (
            "editPage(", "attachPage(", "detachPage(",
            "archiveSlug(", ">Archive<", ">Edit<", "action-btn",
        ):
            self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
