"""Tests for UI3D-C3 Part B: Admin Enter Key Support.

static/admin.html now wires a scoped onkeydown="onEnterTrigger(event, fn)"
handler on a small set of single-line inputs whose section already has one
clear primary action button, calling that SAME existing JS function Enter
would trigger via click — no duplicated business logic, no global/document
keydown listener.

These are static-HTML structural assertions (this project has no JS test
runner) rather than executed-DOM assertions: they verify presence/absence
of the wiring in the served admin.html, matching how UI3D-A/B/C1/C2's
frontend changes are also verified structurally in this test suite.

Covers:
  1. Enter on the Find (exact slug lookup) input wires to lookupSlugDirect(),
     the same function the Find button's onclick calls
  2. Enter on the Search Slug Info (phone) input wires to searchSlugInfo(),
     the same function the Search Slug Info button's onclick calls
  3. click behavior (onclick attributes) is unchanged for both buttons
  4. neither <textarea> (Create Page / Edit Page JSON content) has an
     onkeydown handler — multiline input is never hijacked
  5. no destructive action (archive/restore/detach) gained an onkeydown
     handler, and no document-level/global keydown listener was added
  6. every additional single-primary-action input identified in the full
     audit (Attach Media, Attach Page, Create Bot Client, Assign Slug to
     Bot Client, and the two per-card dynamic inputs) is wired to the SAME
     existing function its button already calls
  7. multi-field / textarea / conditional-select forms (Create New Link,
     Upload Media, Create Page, Edit Page) and the per-card Edit Info
     (client_name/phone/notes) form were NOT wired — confirmed by absence
     of onkeydown on every one of their inputs
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ADMIN_HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html")


class EnterKeySupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    # ── 1. Find input -> lookupSlugDirect() ──────────────────────────────────
    def test_find_input_enter_triggers_lookup_slug_direct(self):
        m = re.search(r'<input[^>]*id="s-slug"[^>]*>', self.html)
        self.assertIsNotNone(m, "s-slug input not found")
        self.assertIn('onkeydown="onEnterTrigger(event, lookupSlugDirect)"', m.group(0))

    # ── 2. Search Slug Info input -> searchSlugInfo() ────────────────────────
    def test_search_slug_info_input_enter_triggers_search_slug_info(self):
        m = re.search(r'<input[^>]*id="s-phone"[^>]*>', self.html)
        self.assertIsNotNone(m, "s-phone input not found")
        self.assertIn('onkeydown="onEnterTrigger(event, searchSlugInfo)"', m.group(0))

    # ── 3. click behavior unchanged ──────────────────────────────────────────
    def test_find_and_search_buttons_still_have_original_onclick(self):
        self.assertIn('onclick="lookupSlugDirect()">Find</button>', self.html)
        self.assertIn('onclick="searchSlugInfo()">Search Slug Info</button>', self.html)

    # ── 4. textarea multiline input never hijacked ───────────────────────────
    def test_textareas_have_no_onkeydown_handler(self):
        textareas = re.findall(r'<textarea[^>]*>', self.html)
        self.assertTrue(textareas, "expected at least one <textarea> in admin.html")
        for ta in textareas:
            self.assertNotIn("onkeydown", ta)

    # ── 5. no destructive control or global listener gained Enter wiring ────
    def test_no_global_keydown_listener_added(self):
        self.assertNotIn("addEventListener('keydown'", self.html)
        self.assertNotIn('addEventListener("keydown"', self.html)
        self.assertNotIn("document.onkeydown", self.html)

    def test_destructive_action_inputs_have_no_onkeydown(self):
        # Detach Page (pd-slug) is the one clearly destructive-adjacent
        # single-input action in this file — it must not gain Enter wiring.
        m = re.search(r'<input[^>]*id="pd-slug"[^>]*>', self.html)
        self.assertIsNotNone(m, "pd-slug input not found")
        self.assertNotIn("onkeydown", m.group(0))

    def test_onEnterTrigger_helper_defined_once(self):
        self.assertEqual(self.html.count("function onEnterTrigger("), 1)

    # ── 6. additional audited single-primary-action inputs ──────────────────
    def test_attach_media_inputs_wire_to_attach_media(self):
        for input_id in ("at-slug", "at-assetId"):
            m = re.search(rf'<input[^>]*id="{input_id}"[^>]*>', self.html)
            self.assertIsNotNone(m, f"{input_id} input not found")
            self.assertIn('onkeydown="onEnterTrigger(event, attachMedia)"', m.group(0))

    def test_attach_page_inputs_wire_to_attach_page(self):
        for input_id in ("pa-pageId", "pa-slug"):
            m = re.search(rf'<input[^>]*id="{input_id}"[^>]*>', self.html)
            self.assertIsNotNone(m, f"{input_id} input not found")
            self.assertIn('onkeydown="onEnterTrigger(event, attachPage)"', m.group(0))

    def test_create_bot_client_input_wires_to_create_bot_client(self):
        m = re.search(r'<input[^>]*id="bc-name"[^>]*>', self.html)
        self.assertIsNotNone(m, "bc-name input not found")
        self.assertIn('onkeydown="onEnterTrigger(event, createBotClient)"', m.group(0))

    def test_assign_bot_slug_inputs_wire_to_assign_bot_slug(self):
        for input_id in ("bs-clientId", "bs-slug"):
            m = re.search(rf'<input[^>]*id="{input_id}"[^>]*>', self.html)
            self.assertIsNotNone(m, f"{input_id} input not found")
            self.assertIn('onkeydown="onEnterTrigger(event, assignBotSlug)"', m.group(0))

    def test_dynamic_card_assign_bot_client_input_wired(self):
        self.assertIn(
            'id="card-bot-clientId-${index}" placeholder="Bot Client ID" '
            'autocomplete="off" inputmode="numeric" step="1" style="flex:1" '
            "onkeydown=\"onEnterTrigger(event, () => assignSlugFromCard('${escVal(r.slug)}', ${index}))\"",
            self.html,
        )

    def test_dynamic_page_attach_inline_input_wired(self):
        self.assertIn(
            'id="pai-pageId-${index}" placeholder="1" autocomplete="off" '
            "onkeydown=\"onEnterTrigger(event, () => attachPageInline('${escVal(r.slug)}', ${index}))\"",
            self.html,
        )

    # ── 7. multi-field / textarea / conditional forms stay un-wired ─────────
    def test_multi_field_and_textarea_forms_have_no_onkeydown(self):
        excluded_ids = [
            "c-destUrl", "c-name", "c-phone", "c-notes",           # Create New Link
            "mu-displayName",                                       # Upload Media
            "pc-title",                                             # Create Page
            "pe-id", "pe-title",                                    # Edit Page
        ]
        for input_id in excluded_ids:
            m = re.search(rf'<input[^>]*id="{input_id}"[^>]*>', self.html)
            self.assertIsNotNone(m, f"{input_id} input not found")
            self.assertNotIn("onkeydown", m.group(0), f"{input_id} should not have Enter wiring")

    def test_per_card_edit_info_inputs_have_no_onkeydown(self):
        for input_id in ("ef-name-${index}", "ef-phone-${index}", "ef-notes-${index}"):
            pattern = re.escape(f'id="{input_id}"')
            m = re.search(rf'<input[^>]*{pattern}[^>]*>', self.html)
            self.assertIsNotNone(m, f"{input_id} input not found")
            self.assertNotIn("onkeydown", m.group(0))


if __name__ == "__main__":
    unittest.main()
