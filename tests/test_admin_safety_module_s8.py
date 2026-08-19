"""Regression tests for SHADZ Safety Engine v1 Phase S8 (SHADZ Admin Safety
Module + Hardening) -- Admin Panel UI wiring.

Locked S8 split: Admin Panel = Safety management / visibility /
configuration / audit / history; Admin Telegram remains immediate incident
response only. This file covers the Admin Panel UI (static/admin.html)
side of that surface: Overview, Safety Users (visibility + admin-side
activation/deactivation/configuration), Daily Check-in History, Safety
Alert History, and SOS History/Management. The corresponding backend
routes (GET /admin/safety/overview, PATCH /admin/safety/users/{id}, GET
/admin/safety/checkins, GET /admin/safety/daily-states, GET
/admin/safety/alerts, GET /admin/safety/late-checkin-alerts, plus the
pre-existing S6.1/S7 routes) have their own full auth/behavior coverage in
test_admin_safety_backend_s8.py, test_safety_admin_endpoints_s6_1.py, and
test_safety_admin_sos_endpoints_s7.py -- this file follows
test_admin_shell_ui3b.py's existing lightweight style instead: read
static/admin.html directly and assert on structural/JS markers, rather than
re-testing request/response behaviour already covered elsewhere.
"""
import os
import re
import unittest

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminSafetyModuleS8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    # ── Navigation / shell wiring ───────────────────────────────────────

    def test_safety_nav_link_present(self):
        nav_match = re.search(
            r'<nav class="admin-nav"[^>]*>(.*?)</nav>', self.html, re.DOTALL
        )
        self.assertIsNotNone(nav_match, "admin-nav shell navigation not found")
        nav_html = nav_match.group(1)
        self.assertIn('data-nav="safety"', nav_html)
        self.assertIn("Safety", nav_html)

    def test_safety_module_group_and_section_present(self):
        self.assertIn('id="module-safety"', self.html)
        self.assertIn('id="safetySection"', self.html)

    def test_existing_nav_and_section_ids_preserved(self):
        # S8 must not rename DOM hooks relied on by pre-existing JS/onclick wiring.
        for nav_key in ("dashboard", "slugs", "media", "pages", "bot"):
            self.assertIn(f'data-nav="{nav_key}"', self.html)
        for section_id in (
            "createSection", "updateSection", "statsSection",
            "mediaUploadSection", "attachSection", "storageSection",
            "pageCreateSection", "pageEditSection", "pageAttachSection",
            "botSection",
        ):
            self.assertIn(f'id="{section_id}"', self.html)

    def test_safety_section_reachable_from_home_card(self):
        self.assertIn("show('safetySection')", self.html)

    def test_safety_overview_card_present(self):
        self.assertIn('id="ov-safety-value"', self.html)
        self.assertIn('id="ov-safety-hint"', self.html)
        self.assertIn("loadSafetyOverview", self.html)

    # ── Backend route wiring (existing S6.1/S7 API, reused not duplicated) ──

    def test_safety_user_routes_called(self):
        self.assertIn("/admin/safety/users", self.html)
        self.assertIn("/telegram-chat-id", self.html)

    def test_safety_emergency_routes_called(self):
        self.assertIn("/admin/safety/emergencies", self.html)
        self.assertIn("/acknowledge", self.html)
        self.assertIn("/resolve", self.html)

    def test_no_parallel_lifecycle_logic_introduced(self):
        # The strict open -> acknowledged -> resolved transition must stay
        # server-side in safety_notify.py; the admin UI only calls the
        # existing routes and never computes/asserts a new status value.
        self.assertNotIn('"open"', self.html.split("<script>", 1)[1] if "<script>" in self.html else "")

    # ── Hardening: client-side lifecycle gating mirrors server enforcement ──

    def test_acknowledge_action_gated_on_open_status(self):
        self.assertIn("e.status === 'open'", self.html)
        self.assertIn("acknowledgeSafetyEmergency", self.html)

    def test_resolve_action_gated_on_acknowledged_status(self):
        self.assertIn("e.status === 'acknowledged'", self.html)
        self.assertIn("resolveSafetyEmergency", self.html)

    def test_resolve_action_requires_confirmation(self):
        # Resolve stops escalation and is not reversible via this UI --
        # matches the existing codebase convention (bulkDeleteBotClients,
        # deleteBotClient, setBotClientActive) of confirm() before an
        # irreversible/high-consequence admin action.
        resolve_fn = re.search(
            r"async function resolveSafetyEmergency\(.*?\n\s*\}", self.html, re.DOTALL
        )
        self.assertIsNotNone(resolve_fn)
        self.assertIn("confirm(", resolve_fn.group(0))

    def test_telegram_chat_id_input_escaped(self):
        # Rendered SafetyUser fields must go through esc()/escVal() like every
        # other admin card (buildBotClientCard, etc.) -- no raw interpolation
        # of server-controlled display_name/telegram_chat_id into HTML.
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        self.assertIn("esc(u.id)", body)
        self.assertIn("esc(u.display_name)", body)
        self.assertIn("escVal(u.telegram_chat_id)", body)

    def test_telegram_chat_id_save_allows_explicit_clear(self):
        # PATCH contract (safety_admin.py) requires telegram_chat_id to be
        # explicitly int or null -- never omitted/defaulted. The UI must send
        # null for an empty field rather than silently skipping the call.
        save_fn = re.search(
            r"async function saveSafetyUserTelegramChatId\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(save_fn)
        self.assertIn("telegramChatId = null", save_fn.group(0))

    def test_telegram_chat_id_numeric_branch_assigns_parsed_int_exactly_once(self):
        # Regression guard: a prior version of this function had two
        # consecutive `else if (/^-?\d+$/.test(raw))` branches with the
        # first left empty, so a valid numeric Telegram Chat ID never
        # actually got assigned and the PATCH silently sent `{}`. There
        # must be exactly one numeric branch, and it must assign
        # parseInt(raw, 10).
        save_fn = re.search(
            r"async function saveSafetyUserTelegramChatId\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(save_fn)
        body = save_fn.group(0)
        self.assertEqual(body.count("/^-?\\d+$/.test(raw)"), 1)
        self.assertIn("telegramChatId = parseInt(raw, 10);", body)
        # The numeric branch's assignment must immediately follow its own
        # `else if` condition, not sit behind an earlier empty branch.
        numeric_branch = re.search(
            r"else if \(/\^-\?\\d\+\$/\.test\(raw\)\) \{\s*telegramChatId = parseInt\(raw, 10\);",
            body,
        )
        self.assertIsNotNone(numeric_branch)

    def test_safety_emergency_card_escapes_gps_and_status(self):
        build_fn = re.search(
            r"function buildSafetyEmergencyCard\(e\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        self.assertIn("esc(e.status)", body)
        self.assertIn("esc(e.id)", body)
        self.assertIn("esc(e.user_id)", body)

    def test_no_internal_fields_referenced_in_safety_ui(self):
        # SafetyEmergencyOut/SafetyUserOut/SafetyAlertOut/
        # SafetyLateCheckinAlertOut deliberately omit notification_claimed_at
        # / telegram_message_id / delivery_claimed_at / nfc_token /
        # secure_token -- the admin UI must not reference fields the API
        # never returns.
        for internal_field in (
            "notification_claimed_at", "telegram_message_id", "delivery_claimed_at",
            "nfc_token", "secure_token",
        ):
            self.assertNotIn(internal_field, self.html)

    # ── Overview (S8) ────────────────────────────────────────────────────

    def test_overview_panel_present_and_wired(self):
        self.assertIn('id="safetyOverviewPanel"', self.html)
        self.assertIn("loadSafetyOverviewPanel", self.html)
        self.assertIn("/admin/safety/overview", self.html)

    def test_overview_panel_surfaces_required_counts(self):
        panel_fn = re.search(
            r"async function loadSafetyOverviewPanel\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(panel_fn)
        body = panel_fn.group(0)
        for field in (
            "active_safety_users", "today_safe", "today_pending", "today_missed",
            "open_missed_checkin_alerts", "active_sos_incidents",
        ):
            self.assertIn(field, body)

    def test_manage_safety_home_card_loads_all_safety_data(self):
        self.assertIn("loadAllSafetyData()", self.html)
        all_fn = re.search(r"function loadAllSafetyData\(\) \{.*?\n    \}", self.html, re.DOTALL)
        self.assertIsNotNone(all_fn)
        body = all_fn.group(0)
        for call in (
            "loadSafetyOverviewPanel", "loadSafetyUsers", "loadSafetyDailyStates",
            "loadSafetyCheckins", "loadSafetyAlerts", "loadSafetyLateCheckinAlerts",
            "loadSafetyEmergencies",
        ):
            self.assertIn(call, body)

    # ── Safety Users: visibility + admin-side configuration (S8) ────────

    def test_safety_user_card_shows_required_config_fields(self):
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        for field in ("daily_deadline", "early_reminder_minutes"):
            self.assertIn(f"escVal(u.{field})", body)
        # timezone is visible but read-only (see test below) -- rendered via
        # esc(), not as an editable input's value.
        self.assertIn("esc(u.timezone)", body)

    def test_timezone_is_visible_but_not_editable(self):
        # Locked S8 v1 rule: timezone is read live and repeatedly throughout
        # the deadline engine, unlike daily_deadline, so there is no safe
        # "applies only to future rows" story for changing it from the
        # Admin Panel -- it must be visibility-only.
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        self.assertNotIn('id="su-tz-', body)
        self.assertNotIn("su-tz-", self.html)

        save_fn = re.search(
            r"async function saveSafetyUserConfig\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(save_fn)
        self.assertNotIn("timezone", save_fn.group(0))

    def test_activation_deactivation_toggle_present(self):
        self.assertIn("setSafetyUserActive", self.html)
        self.assertIn("is_active", self.html)

    def test_activation_toggle_confirms_before_acting(self):
        toggle_fn = re.search(
            r"async function setSafetyUserActive\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(toggle_fn)
        self.assertIn("confirm(", toggle_fn.group(0))

    def test_config_patch_uses_dedicated_user_config_route(self):
        # Separate from the S6.1 telegram-chat-id route (different
        # set/clear-vs-omit contract) -- PATCH /admin/safety/users/{id}.
        save_fn = re.search(
            r"async function saveSafetyUserConfig\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(save_fn)
        body = save_fn.group(0)
        self.assertIn("/admin/safety/users/${userId}`", body)
        self.assertIn("PATCH", body)
        self.assertNotIn("/telegram-chat-id", body)

    def test_no_safety_user_create_or_delete_action_present(self):
        # Locked S8 scope: activation/deactivation/configuration only --
        # SafetyUser provisioning (create/delete) stays out of scope.
        self.assertNotIn("createSafetyUser", self.html)
        self.assertNotIn("deleteSafetyUser", self.html)

    # ── Daily Check-in History (S8) ──────────────────────────────────────

    def test_daily_checkin_history_sections_present(self):
        self.assertIn('id="safetyDailyStateList"', self.html)
        self.assertIn('id="safetyCheckinList"', self.html)
        self.assertIn("/admin/safety/daily-states", self.html)
        self.assertIn("/admin/safety/checkins", self.html)

    def test_checkin_history_renders_required_gps_fields(self):
        checkin_fn = re.search(
            r"async function loadSafetyCheckins\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(checkin_fn)
        body = checkin_fn.group(0)
        for field in ("c.latitude", "c.longitude", "c.accuracy_m", "c.user_id", "c.checked_in_at"):
            self.assertIn(field, body)

    def test_daily_state_history_renders_status_and_user(self):
        state_fn = re.search(
            r"async function loadSafetyDailyStates\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(state_fn)
        body = state_fn.group(0)
        for field in ("s.user_id", "s.safety_date", "s.status"):
            self.assertIn(field, body)

    # ── Safety Alert History (S8) ────────────────────────────────────────

    def test_alert_history_sections_present(self):
        self.assertIn('id="safetyAlertList"', self.html)
        self.assertIn('id="safetyLateCheckinAlertList"', self.html)
        self.assertIn("/admin/safety/alerts", self.html)
        self.assertIn("/admin/safety/late-checkin-alerts", self.html)

    def test_alert_history_renders_user_status_and_timestamps(self):
        alert_fn = re.search(
            r"async function loadSafetyAlerts\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(alert_fn)
        body = alert_fn.group(0)
        for field in ("a.user_id", "a.status", "a.alert_type", "a.triggered_at", "a.resolved_at"):
            self.assertIn(field, body)

    def test_alert_history_is_read_only_no_action_buttons(self):
        # Locked design: resolution of missed/late alerts happens
        # automatically server-side (safety_notify.resolve_missed_checkin_alert)
        # when a matching check-in lands -- this history view must not offer
        # a manual resolve action that would duplicate that logic.
        alert_fn = re.search(
            r"async function loadSafetyAlerts\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(alert_fn)
        self.assertNotIn("onclick", alert_fn.group(0))

    # ── SOS History / Management (S7 lifecycle, surfaced by S8) ──────────

    def test_sos_emergency_card_shows_full_audit_fields(self):
        build_fn = re.search(
            r"function buildSafetyEmergencyCard\(e\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        for field in ("e.triggered_at", "e.acknowledged_at", "e.resolved_at"):
            self.assertIn(field, body)

    def test_admin_panel_scope_note_present(self):
        # Locked split: Admin Panel = management/visibility/configuration/
        # audit/history; Admin Telegram = immediate incident response only.
        self.assertIn("Admin Telegram", self.html)


if __name__ == "__main__":
    unittest.main()
