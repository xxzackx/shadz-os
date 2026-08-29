"""UI3G-D/E/F: Bot Client Control Centre — search+filter, lifecycle polish,
summary.

static/admin.html is a single-file, no-build-step template — these tests
read the served source and assert structural wiring (same convention as
the UI3D/UI3E/UI3F admin-html tests). No backend changes are involved in
this phase.
"""
import os
import re
import unittest

_ADMIN_HTML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_ADMIN_HTML, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def _fn(self, name):
        m = re.search(
            rf"(?:async )?function {re.escape(name)}\([^)]*\) \{{.*?\n    \}}\n",
            self.html, re.DOTALL,
        )
        self.assertIsNotNone(m, f"{name}() not found")
        return m.group(0)


class SearchFilterTests(_Base):
    def test_search_and_filter_controls_present(self):
        self.assertIn('id="bc-search"', self.html)
        self.assertIn('id="bc-filter"', self.html)
        self.assertIn('oninput="renderBotClients()"', self.html)
        self.assertIn('onchange="renderBotClients()"', self.html)
        for value in ('"all"', '"active"', '"inactive"', '"linked"', '"unlinked"'):
            self.assertIn(f"<option value={value}", self.html)

    def test_client_dataset_is_cached_for_reuse(self):
        load = self._fn("loadBotClients")
        self.assertIn("_allBotClients = Array.isArray(data)", load)
        self.assertIn("renderBotClients()", load)

    def test_render_is_client_side_only_no_extra_fetch(self):
        render = self._fn("renderBotClients")
        self.assertNotIn("fetch(", render)
        summary = self._fn("renderBotSummary")
        self.assertNotIn("fetch(", summary)

    def test_search_matches_required_fields(self):
        render = self._fn("renderBotClients")
        self.assertIn("c.client_name", render)
        self.assertIn("c.telegram_username", render)
        self.assertIn("c.telegram_user_id", render)
        self.assertIn("s.slug", render)
        self.assertIn("toLowerCase()", render)

    def test_status_filter_combines_with_search(self):
        render = self._fn("renderBotClients")
        # status filter evaluated first, then the free-text query
        self.assertIn("if (filter === 'active'", render)
        self.assertIn("if (filter === 'inactive'", render)
        self.assertIn("if (filter === 'linked'", render)
        self.assertIn("if (filter === 'unlinked'", render)
        self.assertIn("if (!query) return true;", render)

    def test_filter_empty_state(self):
        render = self._fn("renderBotClients")
        self.assertIn("No bot clients match your search or filter.", render)

    def test_full_dataset_empty_state_preserved(self):
        load = self._fn("loadBotClients")
        self.assertIn("No bot clients yet.", load)


class LifecyclePolishTests(_Base):
    ACTIONS = (
        "regenerateAccessCode",
        "setBotClientActive",
        "deleteBotClient",
        "unassignBotSlug",
    )

    def test_in_flight_guard_on_every_lifecycle_action(self):
        self.assertIn("let _botActionBusy = false;", self.html)
        for name in self.ACTIONS:
            body = self._fn(name)
            self.assertIn("if (_botActionBusy) return;", body, name)
            self.assertIn("_botActionBusy = true;", body, name)
            self.assertIn("_botActionBusy = false;", body, name)
            self.assertIn("confirm(", body, name)

    def test_regenerate_warns_old_code_invalid(self):
        body = self._fn("regenerateAccessCode")
        self.assertIn("invalid immediately", body)

    def test_deactivate_reactivate_state_aware_and_preserves_slugs(self):
        body = self._fn("setBotClientActive")
        self.assertIn("Reactivate bot client", body)
        self.assertIn("Deactivate bot client", body)
        self.assertIn("Assigned slugs are preserved", body)

    def test_delete_confirm_scopes_to_bot_access_only(self):
        body = self._fn("deleteBotClient")
        self.assertIn("NOT", body)
        self.assertIn("content", body)
        self.assertIn("cannot be undone", body)

    def test_unassign_confirm_names_slug_and_protects_content(self):
        body = self._fn("unassignBotSlug")
        self.assertIn("${slug}", body)
        self.assertIn("not deleted or archived", body)

    def test_actions_refresh_from_authoritative_state(self):
        for name in self.ACTIONS:
            body = self._fn(name)
            self.assertIn("loadBotClients();", body, name)


class SummaryTests(_Base):
    def test_summary_element_present(self):
        self.assertIn('id="bot-summary"', self.html)

    def test_summary_counts_derived_from_full_dataset(self):
        body = self._fn("renderBotSummary")
        self.assertIn("_allBotClients", body)
        for label in ("'Total'", "'Active'", "'Inactive'",
                      "'Telegram Linked'", "'Not Linked'"):
            self.assertIn(label, body)

    def test_summary_rendered_before_filtering(self):
        render = self._fn("renderBotClients")
        # summary computed from the full cache, independent of the filtered list
        self.assertIn("renderBotSummary();", render)
        self.assertLess(render.index("renderBotSummary();"),
                        render.index("_allBotClients.filter("))


if __name__ == "__main__":
    unittest.main()
