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

    def test_page_list_static_section_has_only_filter_controls(self):
        # The static #pageListSection markup carries the search box + filters +
        # Refresh only. Any per-row control is JS-rendered in buildPageCard.
        section = re.search(
            r'<div id="pageListSection".*?</div>\s*\n\s*<!-- Telegram Bot Clients section -->',
            self.html,
            re.DOTALL,
        )
        self.assertIsNotNone(section, "pageListSection block not found")
        body = section.group(0)
        for forbidden in (
            "editPage(", "editPageFromList(", "attachPage(", "detachPage(",
            "archiveSlug(", ">Archive<", ">Edit<", ">Delete<", "action-btn",
        ):
            self.assertNotIn(forbidden, body)

    # ── UI3F-B: Edit by selection / prefill ─────────────────────────────

    def _build_page_card_body(self):
        m = re.search(
            r"function buildPageCard\(p\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(m, "buildPageCard function body not found")
        return m.group(1)

    def _edit_from_list_body(self):
        m = re.search(
            r"function editPageFromList\(pageId\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(m, "editPageFromList function body not found")
        return m.group(1)

    def _edit_page_body(self):
        m = re.search(
            r"async function editPage\(\) \{(.*?)\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(m, "editPage function body not found")
        return m.group(1)

    def test_edit_action_present_on_each_page_card(self):
        body = self._build_page_card_body()
        self.assertIn(">Edit<", body)
        self.assertIn("editPageFromList(${p.id})", body)

    def test_edit_from_list_function_exists(self):
        self.assertRegex(self.html, r"function editPageFromList\(pageId\)")

    def test_edit_from_list_reads_cached_pages_without_fetch(self):
        body = self._edit_from_list_body()
        self.assertIn("_allPages.find(", body)
        self.assertNotIn("fetch(", body)

    def test_edit_from_list_prefills_all_existing_form_fields(self):
        body = self._edit_from_list_body()
        for target in (
            "getElementById('pe-id')",
            "getElementById('pe-title')",
            "getElementById('pe-template')",
            "getElementById('pe-status')",
            "getElementById('pe-content')",
        ):
            self.assertIn(target, body)

    def test_edit_from_list_uses_page_id_and_current_values(self):
        body = self._edit_from_list_body()
        self.assertIn("p.id", body)
        self.assertIn("p.title", body)
        self.assertIn("p.template_type", body)
        self.assertIn("p.status", body)

    def test_edit_from_list_prefills_content_json(self):
        self.assertIn("p.content_json", self._edit_from_list_body())

    def test_edit_from_list_opens_existing_edit_section(self):
        self.assertIn("show('pageEditSection')", self._edit_from_list_body())

    def test_no_duplicate_edit_form_created(self):
        # exactly one Edit Page section, one #pe-id input, one editPage() def
        self.assertEqual(self.html.count('id="pageEditSection"'), 1)
        self.assertEqual(self.html.count('id="pe-id"'), 1)
        self.assertEqual(len(re.findall(r"async function editPage\(\)", self.html)), 1)

    def test_editpage_remains_the_submit_path(self):
        self.assertIn('onclick="editPage()"', self.html)
        self.assertIn("/admin/pages/${encodeURIComponent(pageId)}", self._edit_page_body())

    def _edit_page_success_branch(self):
        # the body of the `} else {` (res.ok) arm of editPage()'s fetch handler
        after_guard = self._edit_page_body().split("if (!res.ok)", 1)[1]
        return after_guard.split("} else {", 1)[1]

    def _edit_page_failure_region(self):
        # everything from the !res.ok check up to (not including) the else arm,
        # plus the catch block — the paths that must NOT navigate
        body = self._edit_page_body()
        err_branch = body.split("if (!res.ok)", 1)[1].split("} else {", 1)[0]
        catch_block = body.split("} catch {", 1)[1]
        return err_branch + "\n" + catch_block

    def test_successful_edit_invalidates_page_list_cache(self):
        # cache reset still lives in editPage()'s success (res.ok) branch
        self.assertIn("_allPages = []", self._edit_page_success_branch())

    def test_successful_edit_hides_edit_section(self):
        # UI3F-B.1 hotfix: show() only hides #home, so the open Edit section
        # must be closed explicitly on success.
        branch = self._edit_page_success_branch()
        self.assertRegex(
            branch,
            r"getElementById\('pageEditSection'\)\.style\.display\s*=\s*'none'",
        )

    def test_successful_edit_reloads_and_returns_to_page_list(self):
        # UI3F-B.1: on success, reload the list then show the list section.
        # The reload is awaited so the list is populated before it is shown.
        branch = self._edit_page_success_branch()
        self.assertIn("await loadPageList()", branch)
        self.assertIn("show('pageListSection')", branch)
        # Full ordering:
        #   _allPages = []
        #   -> hide #pageEditSection
        #   -> await loadPageList()
        #   -> show('pageListSection')
        #   -> showMsg('pl-msg' ...)
        hide_edit = re.search(
            r"getElementById\('pageEditSection'\)\.style\.display\s*=\s*'none'",
            branch,
        )
        self.assertIsNotNone(hide_edit)
        order = [
            branch.index("_allPages = []"),
            hide_edit.start(),
            branch.index("await loadPageList()"),
            branch.index("show('pageListSection')"),
            branch.index("showMsg('pl-msg'"),
        ]
        self.assertEqual(order, sorted(order))

    def test_successful_edit_shows_pl_msg(self):
        self.assertIn("showMsg('pl-msg'", self._edit_page_success_branch())

    def test_failure_path_does_not_hide_edit_or_navigate(self):
        region = self._edit_page_failure_region()
        self.assertNotIn("show('pageListSection')", region)
        self.assertNotIn("loadPageList(", region)
        self.assertNotIn("getElementById('pageEditSection')", region)

    def test_show_function_stays_generic_and_unchanged(self):
        # The hotfix must not touch show(): it still hides only #home and does
        # not sweep every .section.
        m = re.search(r"function show\(sectionId\) \{(.*?)\n    \}", self.html, re.DOTALL)
        self.assertIsNotNone(m, "show() function body not found")
        show_body = m.group(1)
        self.assertIn("getElementById('home').style.display = 'none'", show_body)
        self.assertIn("getElementById(sectionId).style.display = 'block'", show_body)
        self.assertNotIn("querySelectorAll('.section')", show_body)
        self.assertNotIn("pageEditSection", show_body)

    def test_manual_edit_page_workflow_still_present(self):
        for marker in (
            'id="pageEditSection"',
            'id="pe-id"',
            'id="pe-title"',
            'id="pe-template"',
            'id="pe-status"',
            'id="pe-content"',
            'id="pe-btn"',
        ):
            self.assertIn(marker, self.html)

    def test_no_archive_delete_or_attach_controls_in_page_card(self):
        body = self._build_page_card_body()
        for forbidden in (
            "archive", "Archive", ">Delete<", "softDelete",
            "attachPage", "detachPage", "preview", "Preview",
        ):
            self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
