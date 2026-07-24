# SHADZ — Changelog

---

## Activation Engine v1 Phase A1 — Activation Data Foundation

**Date:** 2026-07-24
**Status:** Completed and closed. Data foundation only — no activation routing, Telegram bot activation flow, admin UI, or customer-facing behavior yet.

**Runtime/test commit:**
- `54e0801` — Add Activation Engine data foundation

**Merged production commit:**
- `745d304` — Merge pull request #1 from `claude/activation-engine-v1-phase-a1-69e931`

**Files changed:** `models.py`, `tests/test_activation_engine.py` (new)

**Delivered:**
- New `ActivationRecord` model / `activation_records` table: `id`, `slug` (unique, FK → `redirect_links.slug`), `activation_status` (default `unactivated`, not null), `activation_token` (unique, not null), `owner_client_id` (nullable, FK → `bot_clients.id`), `activated_at` (nullable). `content_type` is never duplicated onto this table — it always comes from the corresponding `redirect_links` row.
- Database-level `CheckConstraint` (`ck_activation_records_activation_status`) restricting `activation_status` to `'unactivated'` / `'activated'` — enforced by SQLite itself, not just application code, and proven by a test that asserts `IntegrityError` on an invalid value.
- `create_activation_record_for_slug(db, slug, activation_token)` — looks up the existing `RedirectLink` by slug, rejects a missing slug or a `content_type` other than `url`/`media` (in particular rejects `page`) with `ValueError`, then stages (`add`/`flush`, no commit) a new `unactivated` `ActivationRecord` with no owner and no `activated_at`. Does not generate tokens, does not create a `BotClient`, does not assign a `BotClientSlug`.
- `delete_activation_lifecycle_for_slug(db, slug)` — stages deletion of the slug's `ActivationRecord` (if any) and its `BotClientSlug` assignment (if any) within the caller's existing transaction; never deletes the `BotClient` row; never touches `redirect_links`. No internal commit/rollback — both deletes are only durable (or discarded) together, by whatever commit/rollback the caller performs.
- New `tests/test_activation_engine.py` — 17 stdlib-`unittest` tests, isolated in-memory SQLite (no `main.py`, no real `shadz.db`), covering: table/model creation, default `unactivated` status, nullable `owner_client_id`/`activated_at` before activation, DB-level rejection of an invalid `activation_status`, unique `slug` and unique `activation_token` constraints, the creation helper for `url` and `media` slugs, `page`-slug and nonexistent-slug rejection, no-auto-commit behavior (proven via same-session rollback rather than a brittle cross-session check, since SQLite `:memory:` shares its underlying connection across sessions on one thread), activation-record and `BotClientSlug` cleanup on the lifecycle helper, `BotClient` survival after cleanup, and confirmation that existing `url`/`media`/`page` `redirect_links` rows are unaffected by the new table.

**Important limitations (by design for Phase A1):**
- SQLite foreign-key enforcement (`PRAGMA foreign_keys=ON`) is not globally enabled — consistent with the rest of this schema (`slug_media`, `page_slug_attachments`, `bot_client_slugs`). The `slug → redirect_links.slug` and `owner_client_id → bot_clients.id` foreign-key definitions are present in the SQLite table schema; SQLite is not currently enforcing them because `PRAGMA foreign_keys=ON` is not enabled globally.
- `delete_activation_lifecycle_for_slug` is not wired into any production route or call site, because SHADZ OS currently has no hard-delete path for `redirect_links` — slugs are only archived/restored (`link_admin.py`), never hard-deleted. The helper exists and is tested so it is ready for whichever future path performs that deletion.
- Activation routing, token consumption, ownership activation, `BotClient` creation/assignment tied to activation, admin UI, and the Telegram activation flow are explicitly out of scope for Phase A1.
- `page` slugs remain excluded from Activation Engine v1 — only `url` and `media` are activation-eligible.

**Safety boundaries:** no redirect, Telegram bot, admin UI, Page Engine, Nginx, Cloudflare, R2, or deployment-architecture changes. No existing route, model, or dispatch behavior modified — `activation_records` is a fully additive new table.

**Verification:**
- Local: 17/17 focused tests passed (`python3 -m unittest tests.test_activation_engine`); full suite 56/56 passed (`python3 -m unittest discover -s tests`); `git diff --check` clean
- Pushed branch `claude/activation-engine-v1-phase-a1-69e931` to `origin`; merged into `master` via PR #1 (`745d304`)
- VPS `HEAD` and `origin/master` both confirmed at `745d304`; `shadz.service` restarted; local `/health` readiness wait passed before public checks
- Public checks passed: `/health` 200, `/` 200, `/admin` unauthenticated 401
- Production SQLite confirmed: `activation_records` table exists with columns `id`, `slug`, `activation_status`, `activation_token`, `owner_client_id`, `activated_at`; `CHECK (activation_status IN ('unactivated', 'activated'))` present; unique indexes present on `slug` and `activation_token`; foreign-key definitions present for `slug → redirect_links.slug` and `owner_client_id → bot_clients.id`; initial production `activation_records` row count is 0

**Touched:** `models.py`, `tests/test_activation_engine.py` (new)
**Database:** additive migration — new `activation_records` table only; no existing table altered
**Schema:** `ActivationRecord` added to `models.py`; no other model changed
**Backend/routes/API:** unchanged — no new endpoints
**Authentication:** untouched
**Redirect/Media/Page Engine dispatch:** untouched
**Telegram Bot:** untouched
**Admin UI:** untouched

**Final production runtime state:** `745d304`

**Next roadmap phase:** activation routing, token consumption, ownership activation, and the Telegram/admin activation flow are not yet started.

---

## Page Engine v1 Phase 4N — Production Polish / v1 Closure

**Date:** 2026-07-15
**Status:** Completed and closed. **Page Engine v1 is now complete and closed.**

**Runtime/test commits:**
- `2f7cf8d` — Add Page Engine admin regression tests
- `5862b36` — Harden Telegram tests and sanitize bot errors

**Files changed:** `tests/test_page_admin.py` (new), `bot_runtime.py`, `tests/test_bot_runtime.py`

**Delivered:**
- Read-only audit found `page_admin.py` (create/update/attach/detach) had zero automated test coverage. Added `tests/test_page_admin.py` — 17 tests against an isolated in-memory SQLite database (no `main.py`, no real `shadz.db`), covering template/status/title validation, partial-update field preservation, attach content-type/existence checks, re-attach history preservation, and detach no-op/success behaviour. No Page Engine runtime code changed.
- Reviewed whether `Page.status` (`draft`/`ready`/`archived`) should gate public rendering. Decision: **left unchanged** — attach/detach remains the sole publish mechanism, consistent with production behaviour since Phase 3A; `status` remains informational only. No runtime change made.
- VPS verification surfaced an incident during Phase 4N: `tests/test_bot_runtime.py` assumed `TELEGRAM_BOT_TOKEN` would be absent in the environment. On the VPS, where the token is configured, this caused the test suite to place real outbound requests to the Telegram Bot API using synthetic test `chat_id` values. Telegram rejected the requests, and the resulting `httpx.HTTPStatusError` was logged via its default string representation, which embeds the full request URL — exposing the bot token in application logs, since Telegram's Bot API places the token directly in the URL path rather than a header. **No token value is recorded in this document.**
- Fix, `bot_runtime.py` only: `_send_message` and `_download_telegram_file` no longer log or raise the raw exception object on an `httpx.HTTPStatusError`. `_send_message` logs only `chat_id`, HTTP status code, and exception class. `_download_telegram_file` raises a sanitized `RuntimeError` containing only a safe operation label and status code, chained with `from None` so the original token-bearing exception can never reach a caller's `logger.exception(...)`. Non-HTTP exceptions are logged by class name only. No change to outbound request payloads, retry behaviour, or the existing fail-safe `if not token` guard.
- Fix, `tests/test_bot_runtime.py`: the 4 existing state-machine tests now patch `bot_runtime._send_message` with `AsyncMock`, removing the environment-dependent assumption — tests are network-isolated regardless of whether `TELEGRAM_BOT_TOKEN` is absent, fake, or real. Added 4 new regression tests (`SendMessageLoggingTests`, `DownloadTelegramFileLoggingTests`) that mock `httpx.AsyncClient` to simulate Telegram HTTP failures and assert the token/API URL never appear in logs or raised exception messages, and that no exception chaining leaks the original error.
- Incident resolution on the VPS: the exposed bot token was rotated, `TELEGRAM_BOT_TOKEN` updated in `.env`, and the Telegram webhook (`setWebhook`) re-registered against the new token. Live Telegram tests passed post-rotation: `/start`, access-code login, URL slug lookup/update, and media slug replacement.

**Safety boundaries:** no database/schema change, no migration, no Page Engine runtime behaviour change, no admin UI change, no route change, no Nginx/systemd/Cloudflare change, no dependency added. Bot runtime change is scoped to error-logging sanitization only — no change to conversation flow, guards, or outbound message content.

**Verification:**
- Local: 39/39 tests passed (`python3 -m unittest discover -s tests`), `py_compile` clean on all touched files, `git diff --check` clean
- Fake-token / socket-blocked proof run: full `tests/test_bot_runtime.py` suite passed with a real-looking fake `TELEGRAM_BOT_TOKEN` set and `socket.socket.connect` hard-blocked, confirming no code path can reach the network regardless of token state
- Local `master` and `origin/master` fast-forwarded to `2f7cf8d` then `5862b36` (two separate fast-forward pushes, no force, no merge commits)
- VPS `/opt/shadz-os` synced to `5862b36`; `HEAD` and `origin/master` matched; 39/39 tests passed on VPS; `shadz.service` restarted; local readiness loop against `http://127.0.0.1:8000/health` reached `200` before public checks
- Public checks passed: `/health` 200, `/` 200, `/admin` unauthenticated 401
- Telegram webhook restored and verified after token rotation; live tests passed for `/start`, access-code login, URL slug lookup/update, and media slug replacement

**Touched:** `tests/test_page_admin.py` (new), `bot_runtime.py`, `tests/test_bot_runtime.py`
**Database:** untouched — no migration
**Schema:** untouched
**Backend/routes/API:** unchanged — logging-only change in `bot_runtime.py`
**Authentication:** untouched
**Page Engine runtime:** untouched — `status` field left informational, attach/detach remains the publish mechanism
**Telegram Bot:** error logging sanitized against secret leakage; token rotated on the VPS following the incident; conversation flow and guards unchanged

**Final production runtime state:** `5862b36`

**Page Engine v1 is now complete and closed as of this phase. No remaining Phase 4N runtime work.**

---

## Page Engine v1 Phase 4M — Data Model / Compatibility Audit

**Date:** 2026-07-14
**Status:** Completed and closed

**Runtime commit:**
- `e4c0551` — Guard bot URL updates against slug type changes

**Files changed at runtime:** `bot_runtime.py` only

**New file:** `tests/test_bot_runtime.py` — 4 automated regression tests (stdlib `unittest`, isolated in-memory SQLite, no network calls)

**Delivered:**
- Read-only data-model and compatibility audit of `url`/`media`/`page` slug types across public runtime, admin controls, Telegram Bot self-service, media attachment, Page Engine, archive/restore, and scan tracking — covering `RedirectLink`, `MediaAsset`, `SlugMedia`, `Page`, `PageSlugAttachment`, `BotClient`, `BotClientSlug`, type conversion rules, legacy/null field handling, and SQLite constraint/orphan risk
- Confirmed one real defect: in `bot_runtime.py`'s `awaiting_confirmation` (Telegram URL replacement) state, the live `RedirectLink` row was reloaded and checked for existence/archive status before writing `destination_url`, but the live `content_type` was never re-checked. If an admin converted a slug from `url` to `media` while a customer's Telegram confirmation was still pending, the confirmed write would silently apply `destination_url` to a slug no longer typed `url`
- Fix: one-line guard extension — `if not link or link.is_archived is True or link.content_type != "url":` — rejects the write and returns the customer to the slug menu when the live row is no longer `url`-typed, using the same existing "slug no longer available" reset behaviour already used for missing/archived slugs. No session-flow redesign; session-cached data (`slugs`, `pending_value`) is still used only for display/navigation, never for the final mutation
- Added `tests/test_bot_runtime.py`: 4 new regression tests — (1) URL confirmation succeeds when the live slug is still `url`; (2) URL confirmation is rejected and `destination_url` is left unchanged when the slug was converted to `media` before confirmation; (3) the pre-existing media-upload guard (`content_type != "media"`) still rejects correctly, confirming unrelated media-replacement behaviour is unchanged; (4) the media-upload state still re-prompts correctly on an unsupported message type
- Production DB read-only audit (VPS, no writes) confirmed **zero findings** for: duplicate active `SlugMedia` rows, orphan `SlugMedia` rows, orphan `BotClientSlug` rows by client, orphan `BotClientSlug` rows by slug, and bot assignments referencing unsupported slug types

**Safety boundaries:** no model, schema, migration, database write, route, admin UI, Nginx, or systemd change. Only `bot_runtime.py`'s Telegram URL-confirmation guard changed; media replacement, admin conversion behaviour, and all other bot states are untouched. Slug type policy is unchanged — `url`, `media`, `page` remain the only official types.

**Verification:**
- Local: 18/18 tests passed (`python3 -m unittest discover -s tests -p "test_*.py"` — 4 new + 14 existing `test_page_renderer.py`), `py_compile` clean, `git diff --check` clean
- Local `master` and `origin/master` synced at `e4c0551` (fast-forward push, no force)
- VPS `/opt/shadz-os` fast-forwarded to `e4c0551`; local readiness against `http://127.0.0.1:8000/health` reached `200` before public checks; `shadz.service` confirmed active
- Public checks passed: `/health` 200, `/` 200, `/admin` unauthenticated 401
- Telegram Bot live test passed: URL slug replacement flow confirmed end to end; redirect behaviour after update confirmed correct
- Production DB read-only audit (see Delivered above) returned zero findings across all five checked categories

**Touched:** `bot_runtime.py`, `tests/test_bot_runtime.py` (new file)
**Database:** untouched — no migration; no mandatory data migration required by this audit
**Schema:** untouched — no schema change made; `idx_slug_media_one_active` (a `SlugMedia` partial unique index matching the existing `PageSlugAttachment` pattern) was identified as **optional future hardening only**, explicitly deferred, not applied
**Backend/routes/API:** unchanged except the one-line guard described above
**Authentication:** untouched
**Telegram Bot:** URL-confirmation write path hardened; media replacement and all other states unchanged
**Public Page Engine rendering:** untouched
**Slug type policy:** unchanged — `url`, `media`, `page` remain the current official types

**Final production runtime state:** `e4c0551`

**Next roadmap phase:** Phase 4N — Production Polish / v1 Closure (Page Engine v1 is not yet fully closed)

---

## Page Engine v1 Phase 4L — Template Structure Stabilization

**Date:** 2026-07-14
**Status:** Completed and closed

**Accepted test commit:**
- `1572fec` — Add Page Engine renderer regression tests

**Files changed at runtime:** none — no route, model, schema, database, admin, bot, public HTML, or deployment behaviour changed

**New file:** `tests/test_page_renderer.py` — 14 automated regression tests (stdlib `unittest`, no DB/FastAPI/`main.py` involved)

**Delivered:**
- Read-only architecture audit of the Page Engine template/rendering flow (public rendering pipeline, admin editing pipeline, template inventory, compatibility guardrails)
- Committed automated renderer behaviour lock covering: `invitation` template full and optional-field behaviour; `brand_product` (brand/product) template full and optional-field behaviour; `child_safety` template full and optional-field behaviour; malformed JSON fallback; non-dictionary JSON fallback; unknown `template_type` fallback; HTML escaping for titles and content values
- A structural stability decision gate: inspected `page_renderer.py` and concluded that its existing internal helpers (`_raw`, `_e`, `_fact_rows`, `_contact_button`, `_contact_href`) already provide adequate, consistent normalization and escaping boundaries across all three templates
- Final decision: **NO_RUNTIME_CHANGE** — no verified structural problem was found that justified a runtime refactor under simplicity/surgical-change rules; Phase 4L therefore closes with test coverage only, not a code change

**Safety boundaries:** no route, model, schema, database, admin UI, bot, Nginx, systemd, or public HTML rendering behaviour changed. `shadz.service` was not restarted since no runtime source file changed.

**Verification:**
- Local: 14/14 tests passed (`python -m unittest discover -s tests -p "test_*.py" -v`), `py_compile` clean, `git diff --check` clean
- Local `master` and `origin/master` synced at `1572fec` (fast-forward merge, no force)
- VPS `/opt/shadz-os` manually fast-forwarded to `1572fec`; VPS verification: 14/14 tests passed with `python3`, compile check passed, diff check passed, `HEAD`/`origin/master`/`origin/HEAD` matched
- Existing untracked VPS backup `shadz.db.backup-before-t1b-live-test-20260701-204318` confirmed untouched

**Touched:** `tests/test_page_renderer.py` only (new file)
**Database:** untouched — no migration
**Schema:** untouched
**Backend/routes/API:** untouched
**Authentication:** untouched
**Telegram Bot:** untouched
**Public Page Engine rendering:** untouched — no runtime refactor performed

**Final production runtime state:** unchanged; `1572fec` is a test-only addition on top of `38e476f`

**Next roadmap phase:** Phase 4M — Data Model / Compatibility Audit (Page Engine v1 remains open — Phase 4M and Phase 4N are not yet started)

---

## Page Engine v1 Phase 4Ka — Check Slug Page Optimisation

**Date:** 2026-07-14
**Status:** Completed and production live-tested

**Runtime commit:**
- `38e476f` — Optimize check slug page attachment workflow

**Files changed at runtime:** `static/admin.html` only (frontend-only)

**Delivered:**
- Page-type Check Slug cards now open Attach/Detach controls inline, at the bottom of the selected card, instead of navigating to the standalone `pageAttachSection`
- Inline panel spans the width of the selected card; no desktop panel-width shift
- Only one inline attachment panel is open at a time — opening another page card's panel closes the previously open one
- Page ID input and attach/detach messages reset correctly whenever a panel is (re)opened
- Attach/Detach success/error messages stay scoped to the correct card
- Resolves the navigation/layout issue deferred from Phase 4K test 6

**Safety boundaries:** URL/media slug cards, the standalone home-menu Attach/Detach Page workflow, backend routes/API contracts, database/schema/models, authentication, Telegram Bot flows, and public Page Engine rendering are all unchanged.

**Verification:**
- Local implementation audit passed (markup placement, escaping, payload/endpoint parity with the standalone workflow, message/state scoping)
- Local browser verification passed: inline panel placement/width, panel toggle/close, cross-card open/close state isolation, mobile layout, URL/media cards unaffected, home-menu standalone workflow unaffected, neighboring grid-row stretching visually acceptable
- Deployed to production; VPS `HEAD`/`origin/master`/`origin/HEAD` aligned at `38e476f`; `shadz.service` restarted; local readiness against `http://127.0.0.1:8000/health` passed before public checks
- Public checks passed: `/health` → 200, `/` → 200, `/admin` unauthenticated → 401
- Production browser live tests passed for all Phase 4Ka behaviors listed above

**Touched:** `static/admin.html` only
**Database:** untouched — no migration
**Schema:** untouched
**Backend/routes/API:** untouched
**Authentication:** untouched
**Telegram Bot:** untouched
**Public Page Engine rendering:** untouched

**Final production runtime state:** `38e476f`

---

## Page Engine v1 Phase 4K — Admin Page UX Polish

**Date:** 2026-07-14
**Status:** Completed and production live-tested

**Runtime commits:**
- `2e54262` — Polish Page Engine form state resets
- `825bab6` — Add Page Engine attachment shortcut
- `6a18965` — Reset Page attachment form state

**Files changed at runtime:** `static/admin.html` only

**Delivered:**
- Create/Edit Page stale result panels (`pc-result`/`pe-result`) reset on navigation
- Edit Page fields clear only after a successful update
- Failed Edit Page requests preserve entered values
- Page-type Check Slug cards include a `Manage Page Attachment` shortcut
- Shortcut prefills the Attach and Detach slug fields
- Shortcut explicitly clears Page ID and stale attach/detach messages
- Attach/Detach form fields reset when leaving the section

**Safety boundaries:** URL/media slug cards, Telegram Bot flows, backend routes, DB/schema, authentication, and public Page Engine rendering remain unchanged.

**Production/live-test result:**
- Tests 1–5 and 7–12 passed
- Test 6 exposed a UX/navigation issue: `pageAttachSection` opens at the bottom of the existing Check Slug results page; desktop layout/width changes unexpectedly; mobile does not show the width issue, but the section still opens at the bottom
- This issue is **not fixed** in Phase 4K — deferred to a separate follow-up phase, **Phase 4Ka — Check Slug Page Optimisation**
- Phase 4K is closed because all implemented functions work; the remaining navigation/layout optimisation is explicitly tracked as 4Ka

**Touched:** `static/admin.html` only
**Database:** untouched — no migration
**Schema:** untouched
**Backend/routes/API:** untouched
**Telegram Bot:** untouched
**Public Page Engine rendering:** untouched

---

## Page Engine v1 Phase 4J — Public Page Visual Polish

**Date:** 2026-07-11
**Status:** Complete and closed — deployed and live-tested

**Runtime commits:** `81656d2` (Polish Page Engine public page visuals), `33b088a` (Fix Page Engine contact-link regressions from Phase 4J)
**Files changed at runtime:** `page_renderer.py` only

**Summary:**
Premium, mobile-first visual polish pass on the public Page Engine templates (`invitation`, `brand_product`, `child_safety`) — the item previously tracked as deferred "Phase 3E." Shared dark/neutral SHADZ visual system with restrained gold accents, stronger typography/spacing hierarchy, hero/header presentation, card-based fact rows, primary/secondary CTA buttons, and safe long-text/long-URL wrapping across all three templates. Adds safe contact-link handling (`tel:`/`mailto:`/`http(s)` only; anything else renders as inert escaped text, never a link). `33b088a` closed three regressions found in post-polish audit: no more double-prefixed `mailto:`/`tel:` links, `tel:` links only generated from genuinely phone-formatted values (so `wa.me/...`/`t.me/...`-style strings are never misread as phone numbers), and Child Safety pages show the actual phone number as visible text again alongside the Call buttons.

**Safety boundaries:** no DB/schema, API/route, scan-tracking, archive/restore, slug-attachment, Admin UI, Link Engine, Media Engine, Telegram Bot, Nginx, Cloudflare, R2, or systemd changes.

**Verification:** local renderer regression checks passed (55 automated checks — templates, XSS/escaping, missing fields, long text, full contact-link classification matrix); production deployment passed — readiness-loop verification against `http://127.0.0.1:8000/health` passed before public checks; public `/health` 200, public `/` 200, public `/admin` unauthenticated 401; manual browser live tests passed for all three templates (mobile + desktop); cross-engine smoke tests passed (`url` slug, `media` slug, archived 410, scan-count increment).

**Final production runtime state:** `33b088a`

---

## Page Engine v1 Phase 4I — Completion Audit

**Date:** 2026-07-11
**Status:** Complete and closed — docs-only, no runtime changes

**Summary:**
Page Engine v1 Phase 4I Completion Audit performed after Phase 4H (NFC legacy route extraction). This was a completion/readiness audit, not a feature phase — no new Page Engine features, no refactors, no Telegram Bot changes beyond read-only conflict verification.

**Audit confirmed intact:**
- Route structure: all route modules correctly registered in `main.py`; `GET /{slug}` public catch-all registered last and guarded by `RESERVED_SLUGS`; `/admin/*` routes protected by the shared `verify_admin` Basic Auth dependency at router level; Telegram bot webhook and admin routes registered before the catch-all with no path overlap with Page Engine routes
- Page slug readiness: `content_type == "page"` has clear, working behavior — public `/{slug}` dispatches to `serve_public_page` (`page_public.py`), which renders the active `PageSlugAttachment` → `Page` row via `_render_page_html` (`page_renderer.py`); no redirect loop or slug-collision risk found (`idx_page_slug_one_active` partial unique index plus deactivate-then-insert logic in `attach_page` enforce one active attachment per slug)
- Redirect/media safety: `url` slugs still 302-redirect correctly; `media` slugs still serve active media or "Media not ready yet" correctly; archived slugs of any content type return the 410 expired-page response before the content_type branch is ever reached; `scan_count`/`updated_at` increment uniformly for all slug types
- Admin UI readiness: Create/Edit/Attach/Detach Page Engine sections in `static/admin.html` are correctly wired to their Phase 3A/4B backend routes; `page` type handling in the Check Slug result cards is cosmetic-only (Destination row shows "Not set", per Patch 5.2) and not misleading or dangerous; existing lifecycle controls (archive/restore/convert) correctly continue to exclude `page` as a conversion target
- Cross-engine boundaries: `attach_page` requires `content_type == "page"`, `attach_media` requires `content_type == "media"`, `convert_link_type` explicitly rejects `page` as source or target — no ambiguity between engines
- Telegram Bot Self-Service conflict check: `bot_admin.py` explicitly rejects `content_type == "page"` slugs from bot client assignment at the application layer; no Page Engine route path overlaps any bot route; Telegram Bot Self-Service code was not modified, only read for this verification

**Verification performed (read-only):**
- `python3 -c "import ast; ast.parse(...)"` on all 12 backend modules (`main.py`, `link_admin.py`, `media_admin.py`, `page_admin.py`, `page_public.py`, `page_queries.py`, `page_renderer.py`, `link_public.py`, `nfc_legacy.py`, `bot_admin.py`, `bot_runtime.py`, `models.py`) → no syntax errors
- `git status --short` → clean before and after audit
- Route registration order, slug-type dispatch, and cross-engine guard clauses inspected directly in source
- `static/admin.html` inspected for Page Engine UI wiring and Destination-row behavior on `page` slugs

**Result:**
No blocking route, lifecycle, or bot-conflict issue found. Page Engine v1 is structurally complete and safe to move forward. Only documentation was updated — the stale "Active slug type policy" section in `docs/PROJECT_STATE.md`, which still described `page` as a future/reserved type, has been corrected to reflect that Page Engine is live and `page` slugs render through it. Deferred items (`GET /admin/pages/{page_id}` read endpoint / Edit Page prefill, Phase 3E visual polish, future Page Engine UX improvements) remain explicitly deferred and were not started as part of Phase 4I.

**Touched:** `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md` only
**Runtime code:** untouched
**Database:** untouched — no migration
**Admin UI:** untouched
**Telegram Bot files:** untouched (read-only verification only)
**Nginx/Cloudflare/systemd/R2:** untouched

---

## Telegram Bot Self-Service Phase T1L — Final Audit / Closure

**Date:** 2026-07-08
**Status:** Complete and closed — docs-only, no runtime changes

**Summary:**
Telegram Bot Self-Service v1 Phase T1L Final Audit / Closure completed. This was a final audit/closure phase, not a feature phase — no new bot features, no runtime redesign, no Admin UI redesign.

**Audit confirmed intact:**
- Route wiring: all `/admin/bot/*` routes protected by existing Basic Auth via `admin_router`; public `POST /bot/telegram/webhook` protected by mandatory `TELEGRAM_WEBHOOK_SECRET` shared-secret header (fails closed if unset); webhook registered before the `/{slug}` catch-all
- Bot client lifecycle: create, list, regenerate access code, deactivate/reactivate, delete, and bulk-delete cleanup (T1K) all present and wired as designed and admin-only
- Slug assignment: only `url`/`media` slugs assignable, archived and `page` slugs rejected, one-slug-per-bot-client enforced
- URL replacement safety: Link Safety Guard (T1F) still blocks SHADZ/internal/local destinations while allowing normal external URLs; Link Engine redirect behavior outside the bot unaffected
- Media replacement safety: still validated against the existing `ALLOWED_MEDIA_TYPES` allowlist from `media_admin.py`, 20 MB size cap enforced, only replaces active media for the assigned media slug
- Admin UI: create/assign/deactivate/regenerate/delete/bulk-delete cleanup controls (T1E–T1K) all wired correctly to their existing routes; no stale state found

**Verification performed (read-only):**
- `python3 -m py_compile main.py bot_admin.py bot_runtime.py` → no errors
- Route registration order and dependency wiring confirmed in `main.py`
- Code inspection of `bot_admin.py`, `bot_runtime.py`, and the bot sections of `static/admin.html`

**Result:**
No runtime/backend/frontend/DB/schema/deployment changes were required. Telegram Bot Self-Service v1 is now closed under current v1 scope and ready for production use.

**Touched:** `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md` only
**Runtime code:** untouched
**Database:** untouched — no migration
**Admin UI:** untouched
**Nginx/Cloudflare/systemd/R2:** untouched

---

## Telegram Bot Self-Service Phase T1K — Bot Test Data Cleanup

**Date:** 2026-07-08
**Runtime commit:** `6523079`
**Status:** Complete, pushed, deployed, production-verified, live-tested, and closed

**Summary:**
Adds an admin-only bulk cleanup workflow so test Bot Clients created during development or live testing can be removed without manual DB edits, while protecting real production slugs, redirect links, media assets, and scan logs.

**Backend change (`bot_admin.py` only):**
- New `BulkClientIdsRequest` schema (`client_ids: list[int]`)
- New `POST /admin/bot/clients/bulk-delete` route — de-duplicates `client_ids`, then for each: deletes only that client's `BotClientSlug` assignment rows (join table) and the `BotClient` row itself; unknown ids are skipped (`status: "not_found"`), not errored
- Delete loop + `db.commit()` wrapped in `try/except Exception: db.rollback(); raise` for transaction safety; no broad exception swallowing
- Does **not** delete or modify `redirect_links`, `slug_media`, `media_assets`, `scan_logs`, or actual slug records — mirrors the existing single-client `DELETE /admin/bot/clients/{id}` route from Phase T1G, just batched
- Returns `{deleted, skipped, errors, results}` — never crashes on empty input

**Admin UI change (`static/admin.html` only):**
- Each Bot Client card gets a "Select for Cleanup" checkbox
- New Select All / Clear Selection controls and a "Delete Selected (Cleanup)" bulk bar, mirroring the existing Check Slug bulk-archive/restore selection pattern
- Confirmation dialog lists the selected Bot Client IDs and explicitly warns that a real customer's bot access/assignments will be removed if selected, while slugs/media/scan data remain untouched either way — plain browser `confirm()`, no type-to-confirm
- Static warning copy above the client list clarifies cleanup only affects Bot Client records, not slugs/media/scan data

**Unchanged:**
- All existing `/admin/bot/*` routes, HTTP methods, response shapes, status codes
- Bot runtime (`bot_runtime.py`), Telegram webhook, public redirect/media/page behavior
- Database schema — no migration
- Page Engine, Media Engine, Link Engine, NFC legacy routes
- Nginx, Cloudflare, systemd, R2

**Local verification (pre-commit):**
- `python3 -m py_compile bot_admin.py` → no errors
- Local throwaway-SQLite-DB testing: full lifecycle (create → list → assign → regenerate code → deactivate → reactivate → single delete → bulk-delete) passed
- Bulk-delete specific cases: mixed valid/duplicate/unknown ids (`[1,2,999,1]`) → correct `deleted:2, skipped:1`; empty array → no-op; a client with an assigned slug left untouched while unrelated test clients were bulk-deleted; the slug previously owned by a deleted test client stayed intact (destination, scan_count, public 302 redirect) and was successfully reassigned afterward with no orphan-row block
- `/health` local 200, `/admin` unauth 401, `/admin` auth 200 confirmed against a running local instance before commit

**Production deploy (2026-07-08):**
- Pushed to `origin master`: `a2c7c3f..6523079`
- VPS pulled `6523079`; `shadz.service` restarted; local readiness loop against `http://127.0.0.1:8000/health` passed before public checks
- Local `/health` → 200 `{"status":"ok"}`, public `https://shadz.io/health` → 200 `{"status":"ok"}`
- Public `https://shadz.io/admin` unauthenticated → 401
- Manual production browser/live tests passed

**Touched:** `bot_admin.py`, `static/admin.html`
**Database:** untouched — no migration
**Schema:** untouched
**Bot runtime:** untouched
**Nginx/Cloudflare/systemd/R2:** untouched

---

## Telegram Bot Self-Service Phase T1J — Regenerate Access Code UI

**Date:** 2026-07-08
**Runtime commit:** `9b13c23`
**Status:** Complete, pushed, deployed, production-verified, live-tested, and closed

**Summary:**
Adds a `Regenerate Access Code` control to each Bot Client card in the Admin panel, so the operator no longer needs curl/manual backend calls to rotate a client's access code.

**Frontend change (`static/admin.html` only):**
- `buildBotClientCard()` gets a new confirmation-gated `Regenerate Access Code` button in the existing button row, alongside Deactivate/Delete
- New `regenerateAccessCode(clientId)` confirms via `confirm()`, POSTs to the existing regenerate-code route, shows the newly generated access code via the existing `bl-msg` message pattern, and calls `loadBotClients()` to refresh all cards so the displayed Access Code field updates immediately

**Backend:** untouched — reuses `POST /admin/bot/clients/{client_id}/regenerate-code` (`bot_admin.py`, added Phase T1) as-is. Route verifies the client exists (404 if not), generates a new 6-char mixed alphanumeric code (existing `_generate_access_code` policy), stores it plain text, and does not touch assigned slugs, Telegram-linked fields, or active status. Old access code is overwritten immediately and cannot be recovered.

**Unchanged:** DB/schema, bot runtime, public routes, assigned slugs, Telegram linked status, Page Engine, Media Engine, Link Engine, NFC legacy routes, redirect behavior, scan tracking, R2 logic, Nginx, systemd.

**Local verification (pre-commit):** `python3 -m py_compile main.py bot_admin.py bot_runtime.py` passed; manual diff review of the isolated `static/admin.html` change.

**Production deploy (2026-07-08):** pushed `33a8df7..9b13c23` to `origin master`; VPS pulled `9b13c23`, `shadz.service` restarted; local readiness loop against `http://127.0.0.1:8000/health` passed before checking public endpoints; public `/health` 200, public `/admin` unauth 401. Manual production browser/live test confirmed: `Regenerate Access Code` button visible on every Bot Client card, Cancel leaves the code unchanged, Confirm shows the new code and refreshes the card, refreshing the Admin page persists the new code, assigned slugs unchanged, Telegram linked status unchanged.

**New operational guardrail documented (`docs/PROJECT_STATE.md`):** after `sudo systemctl restart shadz.service`, wait for local Uvicorn readiness (poll `http://127.0.0.1:8000/health`) before running any production health check — Uvicorn can take a few seconds to become ready after systemd reports the service started, and checking too early can produce a false `502` alarm.

**Touched:** `static/admin.html` only
**Database:** untouched
**Schema:** untouched
**Bot runtime:** untouched

---

## Telegram Bot Self-Service Phase T1I — Check Slug → Bot Client Assign Shortcut

**Date:** 2026-07-06
**Runtime commit:** `57b2229`
**Status:** Complete, pushed, deployed, production-verified, and closed

**Summary:**
Adds a small "Assign to Bot Client" control directly on each Check Slug result card, so the operator no longer has to scroll to the Bot Client section and copy/paste the slug manually.

**Frontend change (`static/admin.html` only):**
- `buildResultCard()` gets a new per-card block (Bot Client ID input + Assign button + message area), inserted after the existing Convert row and before the Edit form — no other row reordered or removed
- New `assignSlugFromCard(slug, index)` reuses the existing `assignBotSlug()` fetch/error-handling pattern: validates Bot Client ID (required, integer-only, readable per-card error), POSTs to the existing `POST /admin/bot/clients/{client_id}/slugs` route with the card's own slug, surfaces the backend's `detail` message on error (including the array-shaped FastAPI validation-error case), and calls `loadBotClients()` to refresh the Bot Client list on success

**Backend:** untouched — reuses `POST /admin/bot/clients/{client_id}/slugs` (`bot_admin.py`) as-is. Existing rules continue to apply unchanged: rejects archived slugs, `page`-type slugs, inactive bot clients, already-assigned slugs, and unknown slugs, each with a readable error surfaced on the card.

**Unchanged:** DB/schema, bot runtime, public routes, Page Engine, Media Engine, Link Engine, NFC legacy routes, analytics, shared-content/campaign logic. Existing Check Slug card controls (Edit Info, Archive/Restore, Convert row, Active Media panel, Destination row visibility rules) verified unaffected.

**Local verification (pre-commit):** manual diff review, brace/paren/bracket balance check on the extracted `<script>` block (no JS runtime available in sandbox), sanity `py_compile` on unmodified backend files.

**Production deploy (2026-07-06):** pushed `f36a72c..57b2229` to `origin master`; VPS pulled and restarted; local/public `/health` 200, public `/admin` unauth 401; manual production browser/live test confirmed: empty ID error, non-integer ID error, valid assign success + Bot Client list refresh, already-assigned error, archived-slug block, and all pre-existing card controls unaffected.

**Touched:** `static/admin.html` only
**Database:** untouched
**Schema:** untouched
**Bot runtime:** untouched

---

## Telegram Bot Self-Service Phase T1H — Lifecycle Audit / Closure (No-Op)

**Date:** 2026-07-06
**Status:** Complete and closed — no runtime changes

**Summary:**
T1H was scoped to add restore/cleanup polish for Bot Client lifecycle. Inspection confirmed the required T1H lifecycle polish was already present after T1G (`df4d384`): deactivate, reactivate (via existing `PATCH is_active`), delete, active/inactive Admin UI state + safe action labels, slug-assignment preservation across deactivate/reactivate, inactive-client blocking in `bot_runtime.py` (login + mid-session), and rejection of new slug assignments to inactive clients. No functional gap was found within T1H's stated scope.

**Verification performed (read-only):**
- `python3 -m py_compile bot_admin.py bot_runtime.py models.py main.py` → no errors
- Confirmed `is_active` gating present in: login check, mid-session re-check, assign-slug guard, PATCH toggle (both directions), delete route
- Confirmed Admin UI status badge, Deactivate/Activate toggle, Delete button, and success/error messaging already implemented in `static/admin.html`

**Runtime touched:** none (`bot_admin.py`, `bot_runtime.py`, `static/admin.html`, DB schema untouched)
**Docs touched:** `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md`

**Explicitly out of scope / future backlog:**
- Bulk Bot Client management
- Deleted-client history / audit trail (would require schema change — deferred until a real need arises)

---

## Telegram Bot Self-Service Phase T1G — Bot Client Deactivate/Delete Control

**Date:** 2026-07-05
**Runtime commit:** `df4d384`
**Status:** Complete, pushed, deployed, production-verified, live-tested, and closed

**Summary:**
Adds Bot Client deactivate/reactivate/delete controls, closing the gap flagged in T1D/T1E where the backend routes existed (`PATCH /admin/bot/clients/{id}`) but had no Admin UI exposure, and no hard-delete route existed at all. Also closes a live-session gap: a client deactivated mid-Telegram-conversation previously stayed authenticated until session expiry/service restart.

**Backend change (`bot_admin.py` only):**
- New `DELETE /admin/bot/clients/{client_id}` route — deletes the client's `BotClientSlug` assignment rows (join table only), then the `BotClient` row itself
- Does **not** delete `RedirectLink` slugs, `MediaAsset` records, or scan/history data — only unassigns them from the deleted client
- Assignment cleanup on delete verified necessary and safe: SQLite has no FK enforcement configured (`database.py`), so leaving orphaned `BotClientSlug` rows would permanently block reassignment of those slugs to any future client; deleting the join rows first avoids that

**Runtime change (`bot_runtime.py` only):**
- `_handle_message` now re-checks `BotClient.is_active` on every authenticated state transition (not just at `awaiting_code` login) — a client deactivated mid-session is immediately kicked back to `awaiting_code` with a clear message, instead of retaining access until the in-memory session naturally expires or the service restarts
- Existing login-time active check (`awaiting_code` state) unchanged in behavior — reused `models.BotClient.is_active.is_(True)` (SQLAlchemy boolean-comparison style, not `== True`) in both the pre-existing login check and the new mid-session check

**Admin UI change (`static/admin.html` only):**
- Each Bot Client card now has a Deactivate/Activate toggle button (label and target state reflect current `is_active`) and a Delete button, both confirm-gated
- Wired to the existing `PATCH /admin/bot/clients/{id}` route and the new `DELETE /admin/bot/clients/{id}` route; reuses the existing `bl-msg` message pattern
- No new sections, no redesign — additive to the existing Bot Client card layout from T1D/T1E

**Unchanged:**
- Slug/URL/media replacement flows — untouched except for the mid-session active re-check gating access to them
- Database schema — no migration (`is_active` column already existed on `bot_clients` since Phase T1)
- Page Engine, Link Engine, Media Engine, R2, Nginx, Cloudflare — untouched

**Local verification (pre-commit):**
- `python3 -m py_compile bot_admin.py bot_runtime.py` → no errors
- `python3 -c "import main"` → succeeds
- Local uvicorn boot: `/health` → 200, `/admin` unauth → 401, `/admin` with Basic Auth → 200, `/` → 200
- Full curl-driven lifecycle: create client → assign slug → deactivate (second assign attempt correctly blocked with 400) → reactivate → delete (assignment row removed; slug immediately reassignable to a new client, confirming no orphan)
- Direct `bot_runtime._handle_message` simulation: deactivating a client mid-session immediately blocks further Telegram actions and resets to login; reactivating restores normal flow on the next message

**Production deploy (2026-07-05):**
- Pushed to `origin master`: `59869e1..df4d384`
- VPS pulled `df4d384`; `shadz.service` restarted; readiness wait passed
- Local `/health` → 200, public `/health` → 200 ✓
- Local `/admin` unauth → 401, public `/admin` unauth → 401 ✓

**Live test (2026-07-05):**
- Admin UI: Deactivate/Activate toggle and Delete confirmed live for a test Bot Client
- Telegram: inactive Bot Client confirmed blocked from login/management; reactivated Bot Client confirmed working again
- Delete tested only on a test client — confirmed the assigned slug itself remained untouched (RedirectLink record intact, unaffected by the delete)

**Touched:** `bot_admin.py`, `bot_runtime.py`, `static/admin.html`
**Database:** untouched — no migration
**Schema:** untouched
**Nginx:** untouched

**Explicitly NOT part of T1G (deferred to Phase T1H):**
- Restore / cleanup polish for Bot Client lifecycle
- Bulk Bot Client management

---

## Telegram Bot Self-Service Phase T1F — Link Safety Guard

**Date:** 2026-07-04
**Runtime commit:** `a7510e1`
**Status:** Complete, pushed, deployed, production-verified, live-tested via Telegram, and closed

**Summary:**
Adds a link safety guard to the bot's `url` slug replacement flow so customers cannot point a slug back at SHADZ itself or an internal/local address (slug chaining / route confusion prevention). `bot_runtime.py` only.

**Runtime change (`bot_runtime.py` only):**
- New `_is_blocked_destination_url()` helper (stdlib `urllib.parse.urlparse`); strips whitespace, lowercases hostname, exact-hostname match against a blocklist
- Called in the `awaiting_new_url` state, after the existing `http://`/`https://` prefix check and before the destination is staged for confirmation/save
- Blocks: `shadz.io`, `www.shadz.io`, `localhost`, `127.0.0.1`, `0.0.0.0` (exact hostname only, not substring — e.g. `notshadz.io` is not blocked), any scheme other than `http`/`https`, and missing/unparseable hostnames
- Blocked attempt: customer stays in `awaiting_new_url` and sees "This link cannot be used because it points back to SHADZ or an internal address. Please send an external public link instead." — no technical detail exposed, retry/`/cancel` unaffected
- Allowed external URLs proceed to confirmation exactly as before

**Unchanged:**
- Media slug replacement flow — untouched
- Admin UI (`static/admin.html`) and admin routes (`bot_admin.py`) — untouched
- Database schema — no migration
- Nginx, auth, existing route paths/response shapes — untouched

**Local verification (pre-commit):**
- `python3 -m py_compile bot_runtime.py` → no errors
- Standalone validator check — allowed (`https://google.com`, `https://instagram.com/example`, `https://t.me/xshadzx`, `https://example.com/path?x=1`) all pass through; blocked (`https://shadz.io/test`, `http://www.shadz.io/test`, `http://localhost:8000/test`, `http://127.0.0.1/test`, `http://0.0.0.0/test`, `ftp://example.com`, `example.com`) all blocked; exact-hostname-only confirmed (`notshadz.io`, `shadz.io.evil.com` not blocked)

**Production deploy (2026-07-04):**
- Pushed to `origin master`: `7453bcb..a7510e1`
- VPS pulled `a7510e1`; `shadz.service` restarted
- Local `/health` → 200, public `/health` → 200 ✓
- Public `/admin` unauthenticated → 401 ✓
- `shadz.service` confirmed active ✓

**Live Telegram test (2026-07-04):**
- User confirmed: `https://shadz.io` blocked with the safety message ✓
- User confirmed: `https://google.com` reached confirmation ✓
- User confirmed: replying `no` cancelled safely ✓
- User confirmed: a blocked link did not break the retry flow ✓

**Touched:** `bot_runtime.py` only
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI/backend:** untouched
**Nginx:** untouched

---

## Telegram Bot Self-Service Phase T1E — Bot Admin UI Polish

**Date:** 2026-07-04
**Runtime commits:** `e74665b`, `23d9934`
**Status:** Complete, pushed, deployed, production-verified, browser/live-tested, and closed

**Summary:**
Frontend-only cleanup pass on the Phase T1D Bot Admin UI. No new routes, no backend, DB, bot runtime, Nginx, or R2 changes. Two commits, both touching `static/admin.html` only.

**Frontend changes (`static/admin.html` only):**

`e74665b` — Polish bot admin UI state handling:
- `goHome()` now also resets the Bot Client create result box (`bc-result`), matching the existing reset pattern already used for `createResult` (Link Engine) and `mu-result` (Media Engine) — the create result no longer shows a stale client ID/access code from a previous visit to the section
- `createBotClient()` auto-fills the Assign Slug `Bot Client ID` field (`bs-clientId`) with the newly created client's `id`, removing a manual re-typing step between Create Bot Client and Assign Slug

`23d9934` — Polish bot admin client status and errors:
- `buildBotClientCard()` adds a `Telegram` status row, using the `telegram_username` / `telegram_user_id` fields already returned by `GET /admin/bot/clients` (no backend change — these fields existed since Phase T1 and are populated by `bot_runtime.py` on customer login): shows `@username` if linked with a username, `Linked` if only the numeric Telegram user id is set, or a muted `Not linked yet` otherwise
- `assignBotSlug()` now detects when the backend's error `detail` is an array (FastAPI's validation-error shape, e.g. a non-integer Bot Client ID) and shows a readable `"Invalid Bot Client ID. Please enter a whole number."` message instead of `[object Object]`; this fix is scoped to `assignBotSlug()`'s own error branch only — the shared `showMsg()` helper and every other section's `data.detail || ...` error handling (Link/Media/Page Engine) are untouched

**Explicitly NOT part of T1E (deferred, per scope):**
- Campaign / shared-content / bulk keychain management architecture
- Delete/deactivate bot client UI (backend routes `POST /admin/bot/clients/{id}/regenerate-code` and `PATCH /admin/bot/clients/{id}` still exist but remain unexposed in the UI, same as T1D)
- Check Slug card integration for bot client assignment
- Any bot runtime (`bot_runtime.py`) redesign or behavior change

**Unchanged:**
- `bot_admin.py`, `bot_runtime.py`, `models.py` — not modified
- All existing `/admin/bot/*` route paths, HTTP methods, response models, status codes — identical
- Database schema — no migration
- Page Engine / Link Engine / Media Engine — not touched
- Nginx, R2 — not touched

**Local verification (pre-commit, both commits):**
- `python3 -m py_compile` on all `.py` files → no errors (no `.py` files touched) ✓
- `git diff --name-only` confirmed only `static/admin.html` changed in each commit ✓
- ID/reference sanity grep (`bc-result`, `bs-clientId`, `telegramStatus`, `Invalid Bot Client ID`) confirmed no dangling or duplicate DOM references ✓
- `from main import app; import bot_admin, bot_runtime` → import OK; all 7 bot-related routes still registered correctly ✓

**Production deploy (2026-07-04):**
- Pushed to `origin master`: `deadfb6..23d9934`
- VPS pulled `23d9934`; `shadz.service` restarted; readiness wait used before checks
- Local `/health` → 200, public `/health` → 200 ✓
- Local and public `/admin` unauthenticated → 401 ✓
- `shadz.service` confirmed active ✓

**Browser/live test (2026-07-04):**
- User confirmed: Bot client cards show Telegram linked status / "Not linked yet" correctly ✓
- User confirmed: Create Bot Client auto-fills Assign Slug Bot Client ID ✓
- User confirmed: an invalid decimal Bot Client ID shows the readable error message instead of `[object Object]` ✓

**Touched:** `static/admin.html` only (both commits)
**Database:** untouched — no migration
**Schema:** untouched
**Backend:** untouched
**Bot runtime:** untouched
**Nginx:** untouched

---

## Telegram Bot Self-Service Phase T1D — Basic Bot Admin UI

**Date:** 2026-07-04
**Runtime commit:** `67fad4e`
**Status:** Complete, pushed, deployed, production-verified, browser/live-tested, and closed

**Summary:**
Added a basic Admin Panel UI section for managing Telegram Bot Self-Service clients, wired to the existing `/admin/bot/*` backend routes from Phase T1. No backend, webhook, DB schema, or route behavior changed.

**Frontend changes (`static/admin.html` only):**
- New "Telegram Bot Clients" module on the admin home screen (Module D)
- `botSection` — create bot client (client name → returns and displays `access_code`), assign slug to bot client (client ID + slug), client list (card grid) showing id, client name, access code, active/inactive status, and assigned slugs with per-slug Unassign button, plus a Refresh button
- `createBotClient()`, `assignBotSlug()`, `unassignBotSlug()`, `loadBotClients()`, `buildBotClientCard()` — follow existing JS patterns (`credentials: 'same-origin'`, `esc()`/`escVal()` XSS-safe rendering, `showMsg()`)

**Backend routes reused (no backend changes):**
- `POST /admin/bot/clients` — create client
- `GET /admin/bot/clients` — list clients + assigned slugs
- `POST /admin/bot/clients/{id}/slugs` — assign slug
- `DELETE /admin/bot/clients/{id}/slugs/{slug}` — unassign slug

**Unchanged:**
- No backend changes — `bot_admin.py` not modified
- No webhook/runtime flow changes — `bot_runtime.py` not modified
- No DB schema changes
- No Page Engine / Link Engine / Media Engine behavior changes

**Local verification (pre-commit):**
- `python3 -m py_compile` on all `.py` files → no errors ✓
- Local server started against a throwaway SQLite DB: `/health` → 200, `/admin` unauth → 401, `/admin` auth → 200 ✓
- Full create → assign → list → unassign flow exercised via curl against the real routes to confirm JSON shape matches the new JS ✓
- Served `/admin` HTML diffed byte-for-byte against the file on disk ✓

**Production deploy (2026-07-04):**
- Pushed to `origin master`: `a4a26c0..67fad4e`
- VPS pulled `67fad4e`; `shadz.service` restarted; readiness wait used before checks
- Local `/health` → 200, public `/health` → 200 ✓
- Local and public `/admin` unauthenticated → 401 ✓
- Deployed `/admin` HTML confirmed to contain the Telegram Bot Clients UI markers ✓
- No service errors in recent logs ✓

**Browser/live test (2026-07-04):**
- User confirmed: Create Bot Client, Assign Slug, assigned slug appears on refresh, Unassign all passed ✓

**Touched:** `static/admin.html` only
**Database:** untouched — no migration
**Schema:** untouched
**Backend:** untouched
**Webhook/runtime:** untouched
**Nginx:** untouched

---

## Telegram Bot Self-Service Phase T1C — Media Slug Replacement

**Date:** 2026-07-02
**Runtime commit:** `d126dbc`
**Status:** Complete, pushed, deployed, production-verified, live-tested, and closed

**Summary:**
Added Telegram media slug replacement on top of Phase T1B. Customers with an assigned `media` slug can now send a replacement photo, document, video, or GIF directly in the Telegram chat; the bot downloads it from Telegram, validates it, uploads it to R2, and swaps it in as the new active media — replacing the previous "not available yet, contact support" deferred message. `url` slug replacement behavior from T1B is unchanged.

**Code changes (`bot_runtime.py` only — no other file modified):**
- New session state `awaiting_media_upload`, entered when a customer selects an assigned `media` slug (replaces the old deferred-message branch)
- `_extract_media_candidate(message)` — pulls `(file_id, mime_type, file_size, file_name)` from Telegram `document` / `video` / `animation` / `photo` message fields; returns `None` for plain text or any unsupported message type (voice, sticker, contact, location, etc.)
- `_media_type_for_mime(mime_type)` — reverse-lookup against the **existing** `ALLOWED_MEDIA_TYPES` allowlist, imported directly from `media_admin.py` (not duplicated) — same mime rules the browser upload flow already enforces (JPEG/PNG/WEBP images, MP4/QuickTime/WEBM video, GIF)
- `_download_telegram_file(file_id)` — `getFile` + Telegram file URL download via `httpx.AsyncClient`, hardened to verify `ok == true` and a non-empty `file_path` before proceeding, raising an internal `RuntimeError` (never leaking raw Telegram response text to the customer) on any anomaly
- `_upload_bytes_to_r2(storage_key, data, mime_type)` — new server-side R2 upload path (direct `put_object` via `_get_r2_client()`, imported from `media_admin.py`) — distinct from the existing browser presigned-PUT flow, since the bot has actual file bytes in hand rather than a browser doing the PUT
- Size guard: rejects files above 20 MB (Telegram's own hard cap on `getFile` downloads for the standard cloud Bot API — not an invented limit, since no project-level media size limit exists to reuse) — checked against both Telegram's reported `file_size` (fails fast, no download) and the actual downloaded byte count
- On success: creates a new `MediaAsset` row, deactivates the previous active `SlugMedia` row for the slug, creates a new active `SlugMedia` row, commits — same pattern as the existing `POST /admin/media/attach` route
- Errors (Telegram download failure, unsupported message type, unsupported mime, oversized file, R2 upload failure, DB failure) each get a distinct customer-facing message; internal exception details only reach server logs via `logger.exception`, never the Telegram user
- `_handle_message()` signature extended with a `message: dict` parameter so media fields are available to the state machine; webhook call site updated accordingly

**Reuse note (not a refactor):**
`bot_runtime.py` imports `ALLOWED_MEDIA_TYPES`, `_get_r2_client`, `_make_storage_key`, `_make_public_url` directly from `media_admin.py`. `media_admin.py` itself was not modified — all existing admin media behavior (presigned-PUT browser upload, attach/detach, Storage Manager) is untouched. This mirrors an existing codebase pattern (e.g. Phase 4B's cross-module import of `_get_active_page_attachment`). **Cleanup debt flagged for later:** if a third module ever needs these helpers, extract them into a shared media storage module — deliberately not done in T1C to keep the change surgical.

**Unchanged:**
- `url` slug replacement flow (T1B) — regression-tested, byte-identical behavior
- Database schema — no migration; reuses `media_assets` / `slug_media` (Media Engine v0.1) and `bot_clients` / `bot_client_slugs` (Phase T1)
- `media_admin.py` — not modified
- `.env.example` — no new env vars required
- Admin UI (`static/admin.html`) — not touched; no Bot Self-Service admin UI exists yet

**Local verification (pre-commit):**
- `python3 -m py_compile bot_runtime.py media_admin.py main.py models.py database.py` → no errors ✓
- `from main import app` → import OK, 46 routes registered ✓
- Route table check: `/bot/telegram/webhook` (POST) and `/{slug}` (GET, last) unchanged; all `/admin/*` routes unchanged ✓
- Mocked-payload functional test (in-memory SQLite, mocked `_send_message` / `_download_telegram_file` / `_upload_bytes_to_r2`): plain text rejected, unsupported mime rejected, oversized file rejected, valid photo → uploaded → `MediaAsset` + active `SlugMedia` row created correctly → session resets to menu ✓
- Regression test: full `url` slug access-code → menu → view → replace → confirm flow passed unchanged ✓

**Production deploy (2026-07-02):**
- Pushed to `origin master` as a clean fast-forward: `ba2c31a..d126dbc`
- VPS pulled `d126dbc` by fast-forward
- `shadz.service` restarted; readiness wait passed on attempt 3
- Local `GET /health` → `200 {"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → `200` ✓
- Public `GET https://shadz.io/admin` unauthenticated → `401` ✓
- Public `GET https://shadz.io/bot/telegram/webhook` → `405` (expected — webhook is POST-only) ✓
- `shadz.service` confirmed active/running

**Live Telegram test (2026-07-02):**
- No Admin UI exists for Bot Client management — live test used the existing `/admin/bot/*` API routes directly (`POST /admin/bot/clients`, `POST /admin/bot/clients/{id}/slugs`, `GET /admin/bot/clients`, `DELETE /admin/bot/clients/{id}/slugs/{slug}`, `PATCH /admin/bot/clients/{id}`)
- Temporary `BotClient` "T1C Live Test" created; plaintext `access_code` generated
- Active media slug `media-s9g945` assigned to the temporary client
- Telegram login linked to the customer's Telegram user successfully
- Media replacement flow passed live end to end
- Cleanup performed after test: slug assignment removed (`DELETE /admin/bot/clients/{id}/slugs/{slug}`), temporary `BotClient` deactivated (`PATCH .../is_active=false` — no hard-delete route exists for `BotClient`, so deactivation is the correct and only cleanup path; history is preserved by design)
- No manual DB edits at any point; no schema migration

**Known VPS-only artifact (flagged, not a repo concern):**
An untracked DB backup file, `shadz.db.backup-before-t1b-live-test-20260701-204318`, remains present on the VPS filesystem from live-test prep. It is a local backup artifact only — it must not be committed to the repo and is not referenced by any tracked file.

**Touched:** `bot_runtime.py` (modified only)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched — does not exist yet for Bot Self-Service
**Nginx:** untouched
**New env vars:** none

---

## Telegram Bot Self-Service Phase T1B — Webhook Runtime

**Date:** 2026-07-02
**Runtime commit:** `6a0439c`
**Status:** Complete, pushed, deployed, production-verified, live-tested, and closed (media replacement explicitly deferred to Phase T1C)

**Naming note:** an earlier roadmap draft used "Phase T1B" for the admin UI and "Phase T2" for the webhook runtime. The actual commit and this deployment used "Phase T1B" for the webhook runtime instead. This entry and `PROJECT_STATE.md` follow the commit's naming; the admin UI work is retitled Phase T1C. Flagged for owner awareness, not silently resolved.

**Summary:**
Added the Telegram webhook and customer self-service chat flow on top of the Phase T1 (`28559a3`) Bot Engine admin foundation. Customers authenticate with their plain-text `access_code`, see their assigned `url`/`media` slugs, and can view/replace the `destination_url` of an assigned `url` slug through a confirm step. Media slug replacement is intentionally not implemented — no server-side path exists yet to accept a file from Telegram and push it to R2.

**Code changes:**

New file `bot_runtime.py`:
- `register_bot_webhook_routes(app)` — registers `POST /bot/telegram/webhook`, `include_in_schema=False`; called from `main.py` before the `/{slug}` catch-all
- Webhook auth: mandatory shared-secret header check against `TELEGRAM_WEBHOOK_SECRET`
  - `TELEGRAM_WEBHOOK_SECRET` unset on server → `503`
  - `X-Telegram-Bot-Api-Secret-Token` missing or wrong → `401`
  - Correct header → `200 {"ok": true}`
  - No Basic Auth on this route — Telegram cannot supply it; the shared secret is the sole gate
- `_send_message(chat_id, text)` — outbound Telegram `sendMessage` via `httpx.AsyncClient(timeout=10)` + `response.raise_for_status()`; fails safe (logs an error, does not crash) if `TELEGRAM_BOT_TOKEN` is unset
- `_SESSIONS: dict[int, dict]` — in-memory chat state per `chat_id`; acceptable for a single Uvicorn process (no `--workers`); lost on service restart (owner-approved for T1B)
- `_SEEN_UPDATE_IDS: deque(maxlen=500)` — bounded in-memory dedup of Telegram `update_id`, no DB table
- Chat flow states: access-code entry → slug menu → (url slug) view current destination → submit replacement → confirm → update `redirect_links.destination_url`; media slug selection returns a "replacement not available yet" message and returns to the menu
- No admin functionality reachable through this module

`main.py` changes:
- Added `from bot_runtime import register_bot_webhook_routes`
- Added `register_bot_webhook_routes(app)` call, placed after `register_nfc_routes(app)` and before the `/{slug}` catch-all

`requirements.txt`:
- Added `httpx==0.27.2`

`.env.example`:
- Added `TELEGRAM_BOT_TOKEN` — bot token from @BotFather; if unset, sends fail safe (logged, not crashed)
- Added `TELEGRAM_WEBHOOK_SECRET` — required in production; shared secret checked against Telegram's `X-Telegram-Bot-Api-Secret-Token` header; if unset, webhook fails closed (`503`)

Net: 4 files changed, 330 insertions(+). One new file created. No DB schema change — reuses `bot_clients`/`bot_client_slugs` from Phase T1 (`28559a3`).

**Production deploy (manually performed by Mr.Zack, 2026-07-02):**
- `git pull origin master` on VPS → `6a0439c` pulled successfully
- `httpx` installed on production successfully
- `/opt/shadz-os/.env` updated with `TELEGRAM_BOT_TOKEN` and `TELEGRAM_WEBHOOK_SECRET` (values not recorded in docs)
- `shadz.service` restarted; readiness wait used before checks
- Local `GET /health` → `200 {"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → `200` ✓
- Public `GET https://shadz.io/admin` unauthenticated → `401` ✓

**Production Nginx update (manually performed):**
- Existing config only proxied `/`, `/admin`, `/health`, `/static/`, and the single-segment slug regex — public `/bot/telegram/webhook` initially returned Nginx `404`
- `/etc/nginx/sites-available/shadz.io` backed up before editing
- New `location` block added: `/bot/telegram/webhook` → `http://127.0.0.1:8000/bot/telegram/webhook`, forwarding proxy headers including `X-Telegram-Bot-Api-Secret-Token $http_x_telegram_bot_api_secret_token`
- `nginx -t` passed; `nginx` reloaded successfully
- Public webhook security test: no header → `401`; wrong secret → `401`; correct secret → `200 {"ok":true}` ✓

**Telegram production setup (manually performed):**
- `setWebhook` succeeded for `https://shadz.io/bot/telegram/webhook`
- `getWebhookInfo` confirmed: `url=https://shadz.io/bot/telegram/webhook`, `pending_update_count=0`, no `last_error_message`
- Token/secret values not recorded in docs

**Live Telegram bot verification (2026-07-02):**
- `/start` works ✓
- Wrong access code rejected ✓
- Correct active access code accepted ✓
- Assigned `url` slug list displayed ✓
- Selecting an assigned `url` slug showed current `destination_url` ✓
- Replacement destination URL submitted and confirmed (`YES`) → `redirect_links.destination_url` updated ✓
- Public slug redirect worked after the update ✓
- `scan_count` increment confirmed after public access ✓

**Live test data note:**
- Production DB backup taken before creating T1B live test data
- Test bot client + test `url` slug (`t1b-test-ioayej`) created for live testing; destination pointed at `https://shadz.io/health`
- Test data only — cleanup deferred to Phase T1C if desired

**Deferred to Phase T1C (explicitly not complete):**
- Media slug replacement via Telegram — not implemented; menu/state only, customer told it's deferred
- Any server-side Telegram file-download / R2-upload path
- Live/manual testing of the media-slug deferred-flow message
- Admin UI for Bot Self-Service (bot clients currently managed via raw `/admin/bot/*` API only)
- Optional cleanup of T1B test data

**Unchanged:**
- Database schema — no migration; reuses Phase T1 `bot_clients`/`bot_client_slugs`
- Admin UI (`static/admin.html`) — not touched
- All existing route paths, HTTP methods, response models, status codes
- `/{slug}` catch-all — still registered last
- Public redirect / media / page behavior — identical

**Touched:** `main.py` (modified), `requirements.txt` (modified), `.env.example` (modified), `bot_runtime.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** new location block added for `/bot/telegram/webhook` (production infrastructure change; no secret values recorded)

---

## Phase T1A — Repo Structure Flattening

**Date:** 2026-06-30
**Feature commit:** `ffb526e`
**Merge commit:** `3596ecb`
**Status:** Complete, pushed, deployed, production-verified, VPS-synced, and closed

**Summary:**
All project files previously lived under a `Desktop/shadz-os/` subfolder inside the git repo (`git ls-files` showed paths like `Desktop/shadz-os/main.py`). Phase T1A moved all 28 tracked files/dirs to the repo root using `git mv`, preserving 100% rename history (R100). Local `Desktop/` wrapper removed. VPS fully migrated to the flat layout.

**Git changes:**
- 28 file renames from `Desktop/shadz-os/…` → repo root (all R100)
- `CLAUDE.md` — Rule 13 updated: canonical paths, VPS guardrails
- `docs/PROJECT_STATE.md` — VPS section, Front Page note, Local Git section updated
- `docs/CHANGELOG.md` — this entry

**VPS migration (2026-06-30):**
- `git pull origin master` on VPS — pulled `3596ecb`
- `shadz.db` moved: `/opt/shadz-os/Desktop/shadz-os/shadz.db` → `/opt/shadz-os/shadz.db`
- `.env` moved: `/opt/shadz-os/Desktop/shadz-os/.env` → `/opt/shadz-os/.env`
- `shadz.service` `WorkingDirectory` updated: `/opt/shadz-os/Desktop/shadz-os` → `/opt/shadz-os`
- Nginx `location ^~ /static/` alias updated: `/opt/shadz-os/Desktop/shadz-os/static/` → `/opt/shadz-os/static/`
- Old `/opt/shadz-os/Desktop/shadz-os` wrapper removed from VPS filesystem
- Backups preserved at: `/opt/shadz-os-backups/phase-t1a-wrapper-cleanup-20260629-222954` (do not delete)
- `sudo systemctl daemon-reload && sudo systemctl restart shadz.service`

**Production verification (2026-06-30):**
- `shadz.service` active/running ✓
- Local `GET /health` → 200 ✓
- Public `GET https://shadz.io/health` → 200 ✓
- Public `GET https://shadz.io/admin` unauthenticated → 401 ✓
- Public `GET https://shadz.io/` → 200 ✓
- `/static/index.html` → 200 ✓ | `/static/admin.html` → 200 ✓
- DB intact: `redirect_links=35`, `pages=6`, `bot_clients=0`, `bot_client_slugs=0` ✓
- No `/opt/shadz-os/Desktop/shadz-os` path remains in systemd or Nginx configs ✓

**Canonical roots after T1A:**
- Local: `~/Desktop/shadz-os`
- VPS: `/opt/shadz-os`

**Touched:** 28 file renames, `CLAUDE.md`, `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md`
**Runtime code:** untouched
**Database schema:** untouched
**Admin UI:** untouched
**Routes:** untouched

**Next:** Phase T1B — Admin UI for Bot Self-Service (only after this docs closure is committed, pushed, and VPS-synced)

---

## Telegram Bot Self-Service Phase T1 — Bot Engine Foundation

**Date:** 2026-06-29
**Runtime commit:** `28559a3`
**Status:** Complete, pushed, deployed, production-verified, VPS-synced, and closed

**Summary:**
Added backend foundation for Telegram customer self-service. Phase T1 adds DB tables and admin-only CRUD routes only — no Telegram webhook, no bot token, no Telegram API calls, no chat state machine. New module `bot_admin.py` follows the existing `register_x_admin_routes(admin_router)` pattern. All routes inherit existing Basic Auth from the shared admin router. `main.py` received registration-only changes. Public slug behavior unchanged.

**Changes:**

New file `bot_admin.py`:
- `_generate_access_code(db)` — 6-char code, A-Z + 0-9, `secrets.choice`, must contain ≥1 letter and ≥1 digit, retry up to 10 on collision
- Schemas: `BotClientCreateRequest`, `BotClientUpdateRequest`, `BotSlugAssignRequest`, `AssignedSlugOut`, `BotClientOut`
- Helpers: `_get_bot_client_or_404`, `_build_assigned_slugs`, `_client_out`
- `register_bot_admin_routes(admin_router)` — registers 6 admin routes

Routes added (all 6, all behind existing Basic Auth):
- `POST   /admin/bot/clients` — create client; auto-generate access code
- `GET    /admin/bot/clients` — list all clients with assigned slug metadata
- `POST   /admin/bot/clients/{client_id}/slugs` — assign existing `url`/`media` slug
- `DELETE /admin/bot/clients/{client_id}/slugs/{slug}` — remove assignment (hard-delete row only)
- `POST   /admin/bot/clients/{client_id}/regenerate-code` — regenerate access code
- `PATCH  /admin/bot/clients/{client_id}` — update `client_name` / `is_active`

`models.py` changes:
- Added `BotClient` ORM model → `bot_clients` table
- Added `BotClientSlug` ORM model → `bot_client_slugs` table
- Tables created automatically by existing `Base.metadata.create_all(bind=engine)` on startup — no `_run_migrations()` change needed

`main.py` changes:
- Added `from bot_admin import register_bot_admin_routes`
- Added `register_bot_admin_routes(admin_router)` call after Page Engine registration, before `app.include_router(admin_router)`
- No bot business logic in `main.py`; `/{slug}` catch-all remains last

**Product rules locked in this phase:**
- Access code plain text by owner decision — admin must be able to view it when customers forget
- No phone number verification
- No n8n
- Only `url` and `media` slugs assignable; `page` slugs rejected
- Archived slugs cannot be assigned
- One slug → one bot client only (UNIQUE index on `bot_client_slugs.slug`)
- Deactivating a bot client does NOT delete its slug assignments
- List response includes `content_type`, `notes`, `is_archived`, `assigned_at` per slug for future bot display

**Unchanged:**
- All existing route paths, HTTP methods, response models, status codes
- `/{slug}` catch-all — still registered last
- Public redirect / media / page behavior — identical
- Admin UI (`static/admin.html`) — not touched
- `_run_migrations()` — not touched
- Nginx — not touched

**Production deploy (2026-06-29):**
- DB backup before restart: `shadz.db.backup-before-bot-phase-t1-20260629-211249`
- VPS pulled `28559a3` successfully; `bot_admin.py` confirmed present
- VPS syntax check: `python3 -m py_compile main.py models.py bot_admin.py` → passed ✓
- `shadz.service` restarted; readiness wait used; health became 200 on attempt 3
- `GET /health` local → 200 ✓
- `GET https://shadz.io/health` → 200 ✓
- `GET https://shadz.io/admin` unauthenticated → 401 ✓
- DB tables verified on VPS: `bot_clients`, `bot_client_slugs` present ✓
- Service state: active/running ✓

**Local repo note:**
Runtime commit was pushed from a clean clone at `/Users/Who Am I/Desktop/shadz-os-clean` due to a local Git root problem discovered during this phase (home directory acting as repo root). See PROJECT_STATE.md for full context and future workflow guardrail.

**Touched:** `main.py` (modified), `models.py` (modified), `bot_admin.py` (new)
**Database:** 2 new tables created on startup — no manual migration
**Schema:** `bot_clients` and `bot_client_slugs` added
**Admin UI:** untouched
**Nginx:** untouched

---

## Page Engine v1 Phase 4H — NFC Legacy Route Extraction

**Date:** 2026-06-28
**Runtime commit:** `77b6f2a`
**Status:** Complete, pushed, deployed, production-verified, browser/live-tested, VPS-synced, and closed

**Summary:**
Extracted all NFC legacy and internal utility routes from `main.py` into a new `nfc_legacy.py` module. Routes are re-registered via `register_nfc_routes(app)` (app-level) and `register_nfc_admin_routes(admin_router)` (admin router). `main.py` is now a pure assembly layer — migrations, auth, constants, public routes, and registration calls only. Refactor-only milestone — no behavior change, no schema change, no route change, no admin UI change, no DB migration.

**Changes:**

New file `nfc_legacy.py`:
- X-API-Key auth: `_API_KEY`, `_api_key_header`, `require_api_key` — moved from `main.py`
- Constants: `BOOT_TIME`, `_DF_CMD`, `SAFE_COMMANDS` — moved from `main.py`
- Schemas (8): `CommandRequest`, `CommandResult`, `ServerStatus`, `NFCCreate`, `NFCUpdate`, `NFCAdminUpdate`, `NFCStats`, `NFCResponse` — moved from `main.py`
- `register_nfc_routes(app)` — registers 6 app-level routes
- `register_nfc_admin_routes(admin_router)` — registers 1 admin route

Routes moved (all 7):
- `GET  /status`
- `POST /run-command`
- `POST /nfc`
- `GET  /nfc/{tag_id}`
- `PUT  /nfc/{tag_id}`
- `GET  /r/{tag_id}`
- `PATCH /admin/nfc`

`main.py` changes:
- Removed `import time`, `platform`, `subprocess`, `psutil` (moved to `nfc_legacy.py`)
- Removed `Security`, `APIKeyHeader` from fastapi imports; `BaseModel` from pydantic; `IntegrityError` from sqlalchemy.exc (moved)
- Added `from nfc_legacy import register_nfc_routes, register_nfc_admin_routes`
- Added `register_nfc_routes(app)` call before `/{slug}` catch-all
- Added `register_nfc_admin_routes(admin_router)` call before `register_link_admin_routes()`
- `main.py` reduced from 492 to 302 lines

Net: 2 files changed, 247 insertions(+), 190 deletions(−). One new file created.

**Unchanged:**
- All route paths, HTTP methods, response models, status codes — identical
- X-API-Key behavior for `/status`, `/run-command`, `/nfc/*` — identical
- `/admin/nfc` HTTP Basic auth via `admin_router` — identical
- `/r/{tag_id}` public behavior — identical
- DB behavior — identical
- Public `/{slug}` catch-all — still registered last
- Database schema — no migration
- Admin UI — not touched
- Nginx — not touched

**Local verification (pre-commit):**
- `python -m py_compile main.py nfc_legacy.py` → no errors ✓
- `import nfc_legacy` → import OK ✓
- `import main` → import OK ✓

**Production deploy (2026-06-28):**
- Runtime commit: `77b6f2a`; master fast-forwarded `c9bf2b0` → `77b6f2a`
- VPS pulled master successfully; new file `nfc_legacy.py` confirmed present
- VPS syntax check: `python3 -m py_compile main.py nfc_legacy.py` → passed ✓
- `shadz.service` restarted; readiness wait completed; health became READY ✓
- Local `GET /health` → 200 ✓
- Local `GET /admin` unauthenticated → 401 ✓
- Public `GET https://shadz.io/health` → 200 ✓
- Public `GET https://shadz.io/admin` unauthenticated → 401 ✓

**Browser/live test (2026-06-28):**
- All live tests passed ✓
- User confirmed: all live tests passed ✓

**Touched:** `main.py` (modified), `nfc_legacy.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched

---

## Page Engine v1 Phase 4G — Link Engine Admin Extraction

**Date:** 2026-06-28
**Runtime commit:** `68e9d0e`
**Status:** Complete, pushed, deployed, production-verified, browser/live-tested, VPS-synced, and closed

**Summary:**
Extracted all Link Engine admin route handlers, Pydantic schemas, and slug helper utilities from `main.py` into a new `link_admin.py` module. Routes are re-registered via `register_link_admin_routes(admin_router)` and inherit the existing router's `/admin` prefix and `verify_admin` dependency unchanged. `main.py` now acts cleanly as app assembly / public routes / legacy NFC / router registration layer. Refactor-only milestone — no behavior change, no schema change, no route change, no admin UI change, no DB migration.

**Changes:**

New file `link_admin.py`:
- Slug naming system constants: `VALID_CONTENT_TYPES`, `SLUG_PATTERN`, `_SLUG_CHARS` — moved from `main.py`
- Slug helpers: `is_valid_slug()`, `infer_content_type_from_slug()`, `generate_slug()` — moved from `main.py`
- Schemas (8): `LinkCreate`, `LinkUpdate`, `LinkInfo`, `ActiveMediaInfo`, `LinkSearchResult`, `SearchResponse`, `BulkSlugRequest`, `LinkConvertRequest` — moved from `main.py`
- `register_link_admin_routes(admin_router)` — registers all 10 link admin routes

Routes moved (all 10):
- `POST /admin/link`
- `GET  /admin/link/{slug}`
- `POST /admin/link/{slug}`
- `POST /admin/link/{slug}/archive`
- `POST /admin/link/{slug}/restore`
- `POST /admin/link/{slug}/convert`
- `POST /admin/links/bulk-archive`
- `POST /admin/links/bulk-restore`
- `GET  /admin/links/search`
- `GET  /admin/links/export.csv`

`main.py` changes:
- Removed `import csv`, `io`, `re`, `random`, `string` (moved to `link_admin.py`)
- Removed `Query` from fastapi imports, `StreamingResponse` from fastapi.responses, `or_` from sqlalchemy (moved)
- `IntegrityError` retained — still used by `create_nfc` in `main.py`
- Added `from link_admin import register_link_admin_routes`
- Added `register_link_admin_routes(admin_router)` call before `register_media_admin_routes()`
- Removed all 10 route handlers, 8 schemas, and slug helpers (~675 lines removed)
- `main.py` reduced from 1161 to 492 lines

Net: 2 files changed, 711 insertions(+), 675 deletions(−). One new file created.

**Unchanged:**
- All route paths, HTTP methods, response models, status codes — identical
- All error messages and detail strings — identical
- Auth behavior — `verify_admin` dependency inherited from router unchanged
- CSV export, archive/restore, bulk archive/bulk restore, type conversion, search behavior — identical
- `static/admin.html` — not touched
- Database schema — no migration
- Public `/{slug}` catch-all — still registered last

**Local verification (pre-commit):**
- `python3 -m py_compile main.py link_admin.py` → no errors ✓
- `from main import app` → import OK ✓
- `from link_admin import register_link_admin_routes` → import OK ✓
- All 10 link admin routes confirmed at correct decorators in `link_admin.py` ✓
- `git diff --check` → clean ✓
- No moved symbols remaining in `main.py` ✓

**Production deploy (2026-06-28):**
- Runtime commit: `68e9d0e`; master fast-forwarded `717fb84` → `68e9d0e`
- VPS pulled master successfully; new file `link_admin.py` confirmed present
- `shadz.service` restarted; readiness wait: attempt 1 → `000`, attempt 2 → `200` ✓
- `shadz.service` confirmed `active (running)`; Uvicorn startup complete ✓
- Local `GET /health` → 200 ✓
- Local `GET /admin` unauthenticated → 401 ✓
- Public `GET https://shadz.io/health` → 200 ✓
- Public `GET https://shadz.io/admin` unauthenticated → 401 ✓

**Browser/live admin test (2026-06-28):**
- All admin functions confirmed working ✓
- User confirmed: all live tests passed ✓

**Touched:** `main.py` (modified), `link_admin.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4F — Media Engine Admin Extraction

**Date:** 2026-06-28
**Runtime commit:** `f490ae8`
**Status:** Complete, pushed, deployed, production-verified, browser-tested, VPS-synced, and closed

**Summary:**
Extracted all Media Engine admin route handlers, schemas, and R2 helpers from `main.py` into a new `media_admin.py` module. Routes are re-registered via `register_media_admin_routes(admin_router)` and inherit the existing router's `/admin` prefix and `verify_admin` dependency unchanged. Refactor-only milestone — no behavior change, no schema change, no route change, no admin UI change, no DB migration.

**Changes:**

New file `media_admin.py`:
- R2 helpers: `ALLOWED_MEDIA_TYPES`, `_r2_client`, `_get_r2_client()`, `_make_storage_key()`, `_make_public_url()`, `_generate_presigned_put()` — moved from `main.py`
- Schemas (9): `UploadUrlRequest`, `UploadUrlResponse`, `MediaCompleteRequest`, `MediaCompleteResponse`, `MediaAttachRequest`, `MediaAssetOut`, `SlugMediaOut`, `MediaAssetUpdateRequest`, `MediaDetachRequest` — moved from `main.py`
- `register_media_admin_routes(admin_router)` — registers all 8 routes

Routes moved (all 8):
- `POST /admin/media/detach`
- `POST /admin/media/upload-url`
- `POST /admin/media/complete`
- `POST /admin/media/attach`
- `GET  /admin/media/assets`
- `GET  /admin/media/slug/{slug}`
- `PATCH /admin/media/assets/{media_asset_id}`
- `DELETE /admin/media/assets/{media_asset_id}`

`main.py` changes:
- Removed `import boto3`, `from botocore.config import Config as BotocoreConfig` (moved to `media_admin.py`)
- Removed `func` from `from sqlalchemy import text, func, or_` (no longer used in `main.py`)
- Added `from media_admin import register_media_admin_routes`
- Added `register_media_admin_routes(admin_router)` call before `register_page_admin_routes(admin_router)`
- Removed all 8 route handlers, 9 schemas, and R2 helpers block (~426 lines removed)

Net: 2 files changed, 445 insertions(+), 426 deletions(−). One new file created.

**Unchanged:**
- All route paths, HTTP methods, response models, status codes — identical
- All error messages and detail strings — identical
- Auth behavior — `verify_admin` dependency inherited from router unchanged
- R2 presign flow, upload flow, attach/detach flow — identical
- `static/admin.html` — not touched
- Database schema — no migration
- Public `/{slug}` catch-all — still registered last (index 38 of 39 routes)

**Local verification (pre-commit):**
- `python3 -m py_compile main.py media_admin.py ...` → no errors ✓
- `from main import app` → import OK ✓
- All 8 `/admin/media/*` routes registered exactly once with correct methods ✓
- `/{slug}` catch-all remains last ✓
- No `boto3`/`botocore`/`func` remaining in `main.py` ✓

**Production deploy (2026-06-28):**
- Runtime commit: `f490ae8`; master fast-forwarded `7365374` → `f490ae8`
- VPS pulled master successfully; new file `media_admin.py` confirmed present
- `shadz.service` restarted; readiness wait passed; confirmed `active (running)`
- Local `GET /health` → 200 `{"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- Unauthenticated `GET https://shadz.io/admin` → 401 ✓

**Browser live test (2026-06-28):**
- All 8 `/admin/media/*` routes confirmed working ✓
- Admin opens after Basic Auth ✓

**Touched:** `main.py` (modified), `media_admin.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4E — Public Link Handler Extraction

**Date:** 2026-06-28
**Runtime commit:** `f32ec27`
**Status:** Complete, pushed, deployed, production-verified, browser-tested, VPS-synced, and closed

**Summary:**
Extracted public link/media helper logic from `main.py` into a new `link_public.py` module. The catch-all `@app.get("/{slug}")` route decorator was intentionally kept in `main.py` to preserve FastAPI route ordering safety. Refactor-only milestone — no behavior change, no schema change, no admin UI change, no route change, no new features.

**Changes:**

New file `link_public.py`:
- `_expired_page_html()` — private HTML generator for the archived/410 expired page (moved from `main.py`)
- `_media_page_html(asset)` — private HTML generator for the media render page (moved from `main.py`)
- `_media_not_ready_html(slug)` — private HTML generator for the media-not-ready page (moved from `main.py`)
- `expired_page_response()` — returns the full 410 `HTMLResponse` with no-cache headers
- `serve_public_media(slug, db)` — encapsulates the full media content_type dispatch block

`main.py` changes:
- Added `from link_public import expired_page_response, serve_public_media`
- Removed `HTMLResponse` from FastAPI responses import (no longer used directly in `main.py`)
- Removed `_expired_page_html()`, `_media_page_html()`, `_media_not_ready_html()` — all moved to `link_public.py`
- In `redirect_slug`: archived block → `return expired_page_response()`; media block → `return serve_public_media(slug, db)`
- `@app.get("/{slug}")` route decorator and all routing logic remain in `main.py`

Net: 2 files changed, 136 insertions(+), 118 deletions(−). One new file created.

**Unchanged:**
- All route paths — identical
- All response shapes — identical
- All status codes — identical
- All error detail strings — identical
- Route ordering — `/{slug}` remains last (index 38 of 39 routes)
- url redirect, media render, page render, archived 410, scan_count increment — all untouched
- Admin routes — untouched
- Auth — untouched
- `page_public.py`, `page_queries.py`, `page_renderer.py` — not touched
- `static/admin.html` — not touched
- Database schema — no migration

**Local verification (pre-commit):**
- `python3 -m py_compile main.py link_public.py page_public.py page_admin.py page_queries.py` → no errors ✓
- `from main import app` → import OK ✓
- `import link_public` → `expired_page_response` callable, `serve_public_media` callable ✓
- Route order assertion: `/{slug}` last, all `/admin/*` before it ✓

**Production deploy (2026-06-28):**
- Runtime commit: `f32ec27`; master fast-forwarded `8a7ab37` → `f32ec27`
- VPS pulled master successfully; new file `link_public.py` confirmed present
- `shadz.service` restarted; readiness wait passed (3 seconds); confirmed `active (running)`
- Local `GET /health` → 200 `{"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- Unauthenticated `GET https://shadz.io/admin` → 401 ✓

**Browser live test (2026-06-28):**
- Admin opens after Basic Auth ✓
- Existing URL slug redirects normally ✓
- Existing media slug displays media page normally ✓
- Existing Page Engine page slug displays normally ✓
- Archived slug displays the expired 410 page correctly ✓

**Touched:** `main.py` (modified), `link_public.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4D — Public Page Handler Extraction

**Date:** 2026-06-27
**Runtime commit:** `d502819`
**Deploy/docs baseline:** `87f33b0`
**Status:** Complete, pushed, deployed, production-verified, browser-tested, VPS-synced, and closed

**Summary:**
Extracted public Page Engine page handling out of `main.py` into a dedicated `page_public.py` module. Shared active-attachment query helper moved into a new `page_queries.py` module so that public runtime code does not depend on the admin module. Refactor-only milestone — no behavior change, no schema change, no admin UI change, no route change, no new features.

**Changes:**

New file `page_queries.py`:
- `get_active_page_attachment(slug, db)` — shared DB query helper; returns active `PageSlugAttachment` or `None`; logic identical to the former `_get_active_page_attachment` in `page_admin.py`

New file `page_public.py`:
- `serve_public_page(slug, db)` — public page handler; calls `get_active_page_attachment`, queries `Page` record, calls `_render_page_html`, returns `HTMLResponse`; raises 404 if no attachment or page record missing
- Imports only from `page_queries` and `page_renderer` — no dependency on `page_admin`

`page_admin.py` changes:
- Added `from page_queries import get_active_page_attachment`
- Removed `_get_active_page_attachment` function (moved to `page_queries.py`)
- Updated detach route call site from `_get_active_page_attachment(...)` to `get_active_page_attachment(...)`

`main.py` changes:
- Removed `from page_renderer import _render_page_html` (no longer used directly in `main.py`)
- Changed `from page_admin import register_page_admin_routes, _get_active_page_attachment` → `from page_admin import register_page_admin_routes`
- Added `from page_public import serve_public_page`
- Replaced 7-line page block in `redirect_slug` with `return serve_public_page(slug, db)`

Net: 4 files changed, 36 insertions(+), 20 deletions(−). Two new files created.

**Unchanged:**
- All route paths — identical
- All response shapes — identical
- All status codes — identical
- All error detail strings — identical
- url/media/legacy slug behavior — untouched
- Archive/expired page behavior — untouched
- Admin routes — untouched
- Auth — untouched
- `page_renderer.py` — not touched
- `static/admin.html` — not touched
- Database schema — no migration

**Local verification (pre-commit):**
- `python -m compileall -q .` → no errors ✓
- `python -c "import main; import page_public; import page_admin; import page_queries; print('imports OK')"` → `imports OK` ✓

**Production deploy (2026-06-27):**
- Runtime commit: `d502819`; docs baseline before closure: `87f33b0`
- VPS pulled fast-forward from `e19cc4b` to `87f33b0`; new files `page_public.py` and `page_queries.py` confirmed present on VPS
- `python3 -m compileall -q .` on VPS → no errors ✓
- `sudo systemctl restart shadz.service` completed; readiness wait used before curl checks; app ready after 3 seconds
- `shadz.service` confirmed `active (running)`; Uvicorn showed "Application startup complete"
- Local `GET http://127.0.0.1:8000/health` → 200 `{"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- Unauthenticated `GET https://shadz.io/admin` → 401 ✓

**Browser live test (2026-06-27):**
- Admin → OK ✓
- Page slug public render → OK ✓
- URL slug redirect → OK ✓
- Media slug render → OK ✓
- Phase 4D browser test passed ✓

**Touched:** `main.py` (modified), `page_admin.py` (modified), `page_public.py` (new), `page_queries.py` (new)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4C — Dead Code Removal

**Date:** 2026-06-27
**Commit:** `832a753`
**Status:** Runtime committed locally, docs update in progress, not yet pushed/deployed

**Summary:**
Removed orphaned dead code and corrected a stale docstring in `main.py`. Runtime-cleanup milestone — no behavior change, no feature addition, no schema change, no route change, no admin UI change.

**Changes (`main.py` only):**
- Deleted `_page_placeholder_html()` — 18-line function (def + HTML template + blank separators) orphaned in Phase 3C when `redirect_slug` switched from returning a "Coming soon" placeholder to doing an active-attachment lookup + real render via Page Engine. No callers existed anywhere in the codebase; the Phase 3C CHANGELOG entry had already noted it as no longer called.
- Corrected stale docstring in `redirect_slug`: `page  → placeholder 'Coming soon' page` updated to `page  → renders active attached page via Page Engine (404 if none attached)`, accurately reflecting behavior since Phase 3C.

Net: 1 file changed, 1 insertion(+), 19 deletions(−). `main.py` reduced from 1720 to 1703 lines.

**Unchanged:**
- All routes — identical
- All response shapes — identical
- All public behavior — identical
- Auth — unchanged
- `page_renderer.py` — not touched
- `page_admin.py` — not touched
- `static/admin.html` — not touched
- Database schema — no migration

**Local verification (pre-commit):**
- `python -c "import main; print('import OK')"` → `import OK` ✓
- `grep -n "_page_placeholder_html" main.py` → no output ✓

**Touched:** `main.py` only
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4B — Admin Route Extraction

**Date:** 2026-06-27
**Commit:** `054b4b6`
**Status:** Complete, deployed, production-verified, browser live-tested ✓

**Summary:**
Refactored Page Engine admin/backend logic out of `main.py` into a dedicated `page_admin.py` module. Refactor-only milestone — no behavior change, no schema change, no admin UI change, no route change, no new features.

**Changes (`main.py`, `page_admin.py` new):**

Moved to `page_admin.py`:
- Pydantic schemas: `PageCreateRequest`, `PageUpdateRequest`, `PageOut`, `PageAttachRequest`, `PageDetachRequest`
- Helper functions: `_get_page_or_404`, `_validate_page_template`, `_validate_page_status`, `_get_active_page_attachment`
- Admin route handlers (all 6): `GET /admin/pages/new`, `POST /admin/pages`, `POST /admin/pages/attach`, `POST /admin/pages/detach`, `GET /admin/pages/{page_id}/edit`, `POST /admin/pages/{page_id}`
- Route registration via `register_page_admin_routes(admin_router)` — routes inherit the existing router's `/admin` prefix and `verify_admin` dependency unchanged

`main.py` changes:
- Added: `from page_admin import register_page_admin_routes, _get_active_page_attachment`
- Added: `register_page_admin_routes(admin_router)` call before `app.include_router(admin_router)`
- Removed: all 5 Page Engine schemas, 4 helpers, 6 admin route handlers (~386 lines removed)
- `main.py` is now the app composition layer only

`_get_active_page_attachment` is re-exported from `page_admin.py` and imported back into `main.py` for use in the public `redirect_slug` route. No circular imports — `page_admin.py` never imports from `main.py`.

**Unchanged:**
- All route paths — identical
- All response shapes — identical
- Auth behavior — inherited unchanged from `admin_router`
- Public rendering — `page_renderer.py` untouched
- `static/admin.html` — not touched
- Database schema — no migration
- All other systems — untouched

**Local test results (2026-06-27):**
- `python3 -m compileall -f .` → no errors ✓
- `GET /health` → 200 `{"status":"ok"}` ✓
- `GET /admin` unauthenticated → 401 `{"detail":"Not authenticated"}` ✓
- `GET /admin/pages/new` unauthenticated → 401 ✓ (route exists, auth protected)
- OpenAPI confirms: `POST /admin/pages`, `POST /admin/pages/attach`, `POST /admin/pages/detach`, `POST /admin/pages/{page_id}` all registered ✓

**Production deploy (2026-06-27):**
- VPS pulled `926dcd9` (docs) + `054b4b6` (runtime) via `git pull origin master`
- `python3 -m compileall -f .` on VPS → no errors ✓
- `shadz.service` restarted; confirmed `active (running)`
- Local `GET /health` → 200 `{"status":"ok"}` ✓
- Public `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- Local `GET /admin` unauth → 401 ✓
- Public `GET https://shadz.io/admin` unauth → 401 ✓
- Local `GET /admin/pages/new` unauth → 401 ✓
- Public `GET https://shadz.io/admin/pages/new` unauth → 401 ✓
- Browser live tests: Create Page ✓, Edit Page ✓, Attach Page ✓, Detach Page ✓, active page render ✓, URL slug ✓, Media slug ✓

**Touched:** `main.py` (modified), `page_admin.py` (new file), `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md`
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 4A — Surgical Renderer Extraction

**Date:** 2026-06-26
**Commit:** `e3965f5`
**Status:** Complete, deployed, production-verified ✓

**Summary:**
Refactored Page Engine public rendering logic out of `main.py` into a dedicated `page_renderer.py` module. Refactor-only milestone — no behavior change, no schema change, no admin UI change, no route change, no new features.

**Changes (`main.py`, `page_renderer.py`):**
- Created `page_renderer.py`: contains `_render_page_html()` and its `import html` / `import json` stdlib imports
- Removed `_render_page_html()` from `main.py`; removed `import html` and `import json` (both were exclusively used by that function)
- `main.py` now imports: `from page_renderer import _render_page_html`
- Call site in `redirect_slug` route is byte-for-byte unchanged

**Unchanged:**
- Public rendering behavior — identical output for all templates
- All admin routes — not touched
- Database schema — no migration
- `static/admin.html` — not touched
- All public URLs — unchanged
- Basic Auth — unchanged

**Production deploy (2026-06-26):**
- VPS pulled `357a85e` → `e3965f5` (fast-forward); files: `main.py` (modified), `page_renderer.py` (new)
- `shadz.service` restarted; confirmed `active (running)`
- `GET /health` (local) → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/admin` unauthenticated → 401 ✓
- No `ModuleNotFoundError`, `ImportError`, or `NameError` in service logs ✓

**Touched:** `main.py`, `page_renderer.py` (new file)
**Database:** untouched — no migration
**Schema:** untouched
**Admin UI:** untouched
**Nginx:** untouched
**Auth:** untouched

---

## Page Engine v1 Phase 3D — Admin JSON Helper Guidance

**Date:** 2026-06-26
**Commit:** `357a85e`
**Status:** Complete, deployed, production-verified, browser live-tested ✓

**Summary:**
Added template field guidance and sample JSON helpers to the Page Engine admin UI. When creating or editing a page, the admin now sees the expected `content_json` fields for the selected template, with a "↓ Fill sample JSON" button that inserts valid prettified JSON into the textarea. JSON validation feedback (valid/invalid hint) appears on textarea blur.

**Frontend changes (`static/admin.html`):**
- Template guide div added after template `<select>` in both Create Page and Edit Page sections; hidden by default, populated by JS on template change
- `updateTemplateGuide(prefix)` — renders field list and Fill sample JSON button for the selected template; hides when no template selected (Edit Page "— keep existing —" case); null-guarded
- `fillSample(prefix)` — inserts prettified sample JSON into the content textarea, then triggers validation; null-guarded
- `validateJsonField(prefix)` — on textarea blur: shows ✓ Valid JSON (green) or ✗ Invalid JSON with error message (red); clears when textarea is empty; null-guarded
- Content textarea height increased 80px → 120px; `font-family` changed to monospace for readability
- `updateTemplateGuide('pc')` called at script init — guide appears immediately on Create Page load (invitation pre-selected)

**Sample JSON keys (match `_render_page_html` renderer fields exactly):**
- `invitation`: `message`, `date`, `time`, `venue`, `rsvp_contact`
- `brand_product`: `tagline`, `description`, `contact`
- `child_safety`: `child_name`, `age`, `description`, `contact_name`, `contact_phone`, `contact_phone_2`, `notes`

**Technical note — renderer alignment:**
Sample keys intentionally match the current renderer in `main.py`. If field names change in a future Phase 3E renderer update, samples should be updated in the same commit.

**Unchanged:**
- `main.py` — not touched
- Backend routes — not touched
- DB schema — not touched
- Public renderer behavior — not touched
- All existing admin capabilities — confirmed working

**Production deploy (2026-06-26):**
- VPS pulled `b38ff6e` → `357a85e` (fast-forward); file updated: `static/admin.html`
- `shadz.service` restarted by Mr.Zack
- `GET /health` (local) → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/admin` unauthenticated → 401 ✓
- Browser live test: template guide visible on Create Page load; Fill sample JSON inserts correct JSON; JSON validation hint shows green/red correctly ✓

**Touched:** `static/admin.html` only

---

## Page Engine v1 Phase 3C — Public Page Rendering

**Date:** 2026-06-26
**Commits:** `28c1530` — Add Page Engine public rendering (Phase 3C), `165c0d3` — Fix Phase 3C changelog touched-files note
**Status:** Complete, deployed, production-verified, browser live-tested ✓

**Summary:**
Implemented the public serving path for `page`-type slugs. When an NFC tag pointing to a `page` slug is scanned, the system now looks up the active page attachment, loads the page record, and renders a safe HTML page matching the page's template type. No active attachment returns 404.

**Backend changes (`main.py`):**
- Added `import html` and `import json` (stdlib — no new dependencies)
- Added `_render_page_html(page)` function: parses `content_json` safely, escapes all user text via `html.escape()`, renders per template type (`invitation`, `brand_product`, `child_safety`), falls back to title-only for unknown types
- `invitation` template: renders eyebrow "You are invited", title (h1), optional message, and a details table (Date, Time, Venue, RSVP)
- `brand_product` template: renders title (h1), optional tagline (gold uppercase), description, contact
- `child_safety` template: renders gold "Missing Child" eyebrow, title (h1), details table (Name, Age, Last seen, Contact, Phone, Alt phone, Notes), help note
- Styling: black/gold SHADZ aesthetic, SHADZ wordmark fixed top-center, responsive max-width 480px card, inline CSS only
- Replaced `if ct == "page": return HTMLResponse(content=_page_placeholder_html(slug))` with active-attachment lookup and `_render_page_html` call
- `_page_placeholder_html` remains defined but is no longer called from the public route

**Public behavior after Phase 3C:**
- `page` slug, no active attachment → 404
- `page` slug, active attachment → 200 HTML rendered page
- Archived slug → 410 expired page (unchanged)
- `url` slug → 302 redirect (unchanged)
- `media` slug → media HTML page (unchanged)
- `scan_count` incremented on every non-archived public hit (unchanged behavior — happens before page branch)

**Unchanged:**
- Admin UI (`static/admin.html`) — not touched
- All admin routes — not touched
- url/media slug behavior — not touched
- Archive/restore behavior — not touched
- DB schema/models — not touched

**Local test results:**
- `GET /health` → 200 `{"status":"ok"}` ✓
- `GET /admin` unauthenticated → 401 ✓
- `GET /page-unknown` (unknown slug) → 404 ✓
- `GET /page-xxx` (page slug, no active attachment) → 404 ✓
- `GET /page-xxx` (page slug, active invitation attachment) → 200 HTML with title/content ✓
- `GET /page-xxx` (archived slug) → 410 ✓
- XSS: `<script>` in title → `&lt;script&gt;` in output, raw `<script>` absent ✓
- `child_safety` template renders "Missing Child" label ✓

**Production deploy (2026-06-26):**
- VPS pulled `719b103` → `165c0d3` (fast-forward); files updated: `main.py`, `docs/CHANGELOG.md`
- `shadz.service` restarted manually by Mr.Zack
- Note: immediate curl after restart returned `502 Bad Gateway` — startup timing only; Uvicorn was still initialising. Resolved within seconds once startup completed.
- `shadz.service` confirmed `active (running)`; Uvicorn bound to `http://127.0.0.1:8000`
- `GET /health` (local) → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/health` → 200 `{"status":"ok"}` ✓
- `GET https://shadz.io/admin` unauthenticated → 401 ✓
- Browser live test: public page slug rendered black/gold SHADZ page correctly ✓
- Visual design noted as acceptable for internal testing; not yet polished for client-facing sales use

**Touched:** `main.py`, `docs/CHANGELOG.md`

---

## Page Engine v1 Phase 3B — Admin UI

**Date:** 2026-06-25
**Commit:** `a57fff7`
**Status:** Complete, deployed, production-verified

**Summary:**
Wired Phase 3A backend routes into the admin panel. Added Page Engine as Module C on the admin home screen with three sections: Create Page, Edit Page, and Attach / Detach.

**Frontend changes (`static/admin.html`):**
- Module C: Page Engine added to home screen (after Media Engine)
- Three new home-card tiles: Create Page, Edit Page, Attach / Detach
- `pageCreateSection` — form to create a new page; title (required), template select (`invitation` / `brand_product` / `child_safety`), status select (`draft` / `ready`), optional content JSON textarea; result box shows page ID on success
- `pageEditSection` — partial-update form; page ID required; only filled fields sent in payload (omitted fields preserved server-side); blank select option `"— keep existing —"` prevents accidental overwrites; informational note shown to user
- `pageAttachSection` — two sub-blocks: Attach (page ID + slug → `POST /admin/pages/attach`) and Detach (slug only → `POST /admin/pages/detach`); separated by visual divider with sub-labels
- Four JS functions added: `createPage()`, `editPage()`, `attachPage()`, `detachPage()` — all use `credentials: 'same-origin'`, button-disable during request, `showMsg()` for success/error
- `GRID_SECTIONS` unchanged (new sections are simple form layouts, not card grids)

**Backend routes used (no backend changes — Phase 3A routes only):**
- `POST /admin/pages` — create page
- `POST /admin/pages/{page_id}` — partial update
- `POST /admin/pages/attach` — attach page to slug
- `POST /admin/pages/detach` — detach page from slug

**Remaining limitation:**
Edit Page cannot pre-populate with existing data — no `GET /admin/pages/{page_id}` JSON endpoint exists. The edit form is a partial-update form only. A read endpoint can be added as a future patch if needed.

**Unchanged (confirmed):**
- All existing admin sections — untouched
- All backend files — untouched
- No new routes added
- No DB migration

**Production deploy:**
- DB backup: `shadz.db.backup-before-page-engine-phase3b-20260625-184943`
- VPS pulled `a57fff7` via `git pull origin master`
- `shadz.service` restarted; confirmed `active (running)`
- Local `/health` → `200` `{"status":"ok"}`
- Public `https://shadz.io/health` → `200` `{"status":"ok"}`
- `https://shadz.io/admin` unauthenticated → `401` ✓
- Browser live test: Create Page, Edit Page, Attach/Detach all confirmed working ✓
- All existing admin functions confirmed working ✓

**Touched:** `static/admin.html` only

---

## Page Engine v1 Phase 3A — Admin Backend Routes

**Date:** 2026-06-20
**Commit:** `c6c5a15`
**Status:** Complete, deployed, production-verified

**Summary:**
Added all Page Engine admin backend routes behind existing Basic Auth. No public page rendering. No admin UI. No DB migration.

**Backend changes (`main.py`, +387 lines, 0 deleted):**

Schemas added:
- `PageCreateRequest` — `title`, `template_type`, `status` (default `draft`), `content_json` (optional)
- `PageUpdateRequest` — all fields optional (partial update semantics)
- `PageOut` — full page record response
- `PageAttachRequest` — `page_id`, `slug`
- `PageDetachRequest` — `slug`

Helpers added:
- `_get_page_or_404(page_id, db)` — raises 404 if page not found
- `_validate_page_template(template_type)` — validates against `PAGE_TEMPLATE_TYPES`
- `_validate_page_status(status)` — validates against `PAGE_STATUSES`
- `_get_active_page_attachment(slug, db)` — returns active `PageSlugAttachment` or None

Routes added (all under `admin_router`, Basic Auth protected):
- `GET  /admin/pages/new` — minimal standalone test form (not integrated into admin.html)
- `POST /admin/pages` — create page (draft by default); does not attach to any slug
- `POST /admin/pages/attach` — attach page to slug; validates slug exists with `content_type='page'`; deactivates old active attachment; preserves history
- `POST /admin/pages/detach` — safe no-op deactivation; preserves history; no error if nothing attached
- `GET  /admin/pages/{page_id}/edit` — minimal standalone test form (not integrated into admin.html)
- `POST /admin/pages/{page_id}` — partial update; omitted fields preserved

**Route ordering note:**
`/attach` and `/detach` registered before `/{page_id}` to prevent FastAPI coercing string path segments as int.

**Application-layer FK enforcement:**
Attach route validates slug exists in `redirect_links` with `content_type='page'` before writing. `PRAGMA foreign_keys=ON` still not enabled — consistent with existing production pattern.

**Production deploy:**
- DB backup: `shadz.db.backup-before-page-engine-phase3a-20260620-211430`
- VPS pulled `c6c5a15`
- `shadz.service` restarted; confirmed `active (running)`
- `/health` → 200, `/admin` unauthed → 401 ✓
- `pages` → 0 rows, `page_slug_attachments` → 0 rows ✓

**Touched:** `main.py` only
**Database:** no migration — tables already exist from Phase 2
**Frontend:** untouched

---

## Page Engine v1 Phase 2 — Database Foundation

**Date:** 2026-06-20
**Commit:** `e37a56c`
**Status:** Complete, deployed, production-verified

**Summary:**
Added Page Engine database foundation. Creates `pages` and `page_slug_attachments` tables with idempotent safe migration. No public rendering, no admin routes, no admin UI added.

**Schema changes (`models.py`):**
- `PAGE_TEMPLATE_TYPES = {"invitation", "brand_product", "child_safety"}` — validation constant
- `PAGE_STATUSES = {"draft", "ready", "archived"}` — validation constant
- `Page` model → `pages` table:
  - `id` (PK), `title` (VARCHAR NOT NULL), `template_type` (VARCHAR NOT NULL), `status` (VARCHAR NOT NULL, default `draft`), `content_json` (TEXT nullable), `created_at`, `updated_at`, `archived_at` (nullable)
- `PageSlugAttachment` model → `page_slug_attachments` table:
  - `id` (PK), `page_id` (FK → `pages.id`, indexed), `slug` (FK → `redirect_links.slug`, indexed), `is_active` (BOOLEAN NOT NULL), `created_at`, `updated_at`

**Migration changes (`main.py`):**
- `_run_migrations()` extended with idempotent PRAGMA guards for both new tables
- All `ALTER TABLE ADD COLUMN` definitions are nullable or carry a DEFAULT — safe against tables that already have rows
- Partial unique index created explicitly (cannot be expressed in SQLAlchemy `mapped_column`):
  - `CREATE UNIQUE INDEX IF NOT EXISTS idx_page_slug_one_active ON page_slug_attachments(slug) WHERE is_active = 1`
  - Enforces: one slug → only one active page attachment; inactive/history rows are allowed
- Normal lookup indexes (`page_id`, `slug`) created by `create_all` via `index=True` on model — not duplicated explicitly

**Page Engine rules enforced by DB:**
- One page may attach to many slugs ✓
- One slug may only have one active page attachment ✓ (partial unique index)
- Inactive/history attachment rows allowed ✓

**FK note:**
`PRAGMA foreign_keys=ON` is not enabled — same as existing production pattern (`SlugMedia` has the same situation). FK declarations are ORM metadata only. Application-layer integrity checks to be added in Phase 3A routes.

**Unchanged (confirmed):**
- Public redirect route — untouched
- `url` and `media` slug behaviour — untouched
- Admin UI — untouched
- All existing endpoints — untouched
- Nginx, shadz.service, Cloudflare/R2 — untouched
- Auth — untouched

**Production deploy:**
- DB backup: `shadz.db.backup-before-page-engine-phase2-20260620-195630`
- VPS pulled `e37a56c` via `git pull origin master` (fast-forward from `6dfbb6b`)
- `shadz.service` restarted manually by user; confirmed `active (running)`
- Local health: `http://127.0.0.1:8000/health` → `200` `{"status":"ok"}`
- Public health: `https://shadz.io/health` → `200` `{"status":"ok"}`
- `pages` table exists, 0 rows ✓
- `page_slug_attachments` table exists, 0 rows ✓
- `idx_page_slug_one_active` exists, unique=1, partial=1 ✓
- `redirect_links`: 26 rows — existing data intact ✓
- `media_assets`: 13 rows — existing data intact ✓
- Homepage: 200, admin unauthenticated: 401 ✓

**Workflow note:**
Claude Code has no VPS execution authority. Claude Code handles local code changes, verification, commit, and push when approved. VPS pull, service restart, and production verification are performed manually by user via SSH.

**Touched:** `models.py`, `main.py`
**Database:** new tables created; existing tables untouched
**Schema:** additive only — no existing column or table modified
**Nginx:** untouched
**Auth:** untouched
**Frontend:** untouched

---

## Page Engine v1 Phase 1B — Media Asset Rename

**Date:** 2026-06-19
**Commit:** `1d11005`
**Status:** Complete, deployed, production-verified

**Summary:**
Admin can now rename (or clear) the `display_name` of any existing media asset directly from the Storage Manager. No R2 object, storage key, public URL, or original filename is touched.

**Backend changes (`main.py`):**
- `MediaAssetUpdateRequest` Pydantic model — `{ "display_name": str | None }`
- `PATCH /admin/media/assets/{media_asset_id}` — new endpoint on `admin_router` (Basic Auth protected)
- Only `asset.display_name` is written; all other fields are never touched
- Blank / whitespace-only `display_name` stored as `NULL` (clears the name)
- Works on both active and soft-deleted assets
- Returns `{ success, id, display_name, original_filename }`

**Frontend changes (`static/admin.html`):**
- `_assetMap` — module-level JS object keyed by asset ID; populated by `loadStorage()` before rendering
- `renameAsset(assetId)` — reads current `display_name` from `_assetMap[assetId]`; uses `prompt()` pre-filled with current name; blank input clears name
- `buildAssetCard()` — adds **Add Name** / **Edit Name** button per card; `onclick` passes only integer asset ID (no string data in HTML attributes — XSS-safe)
- Action row now `space-between`: rename button left, delete button right
- On success: `showMsg('st-msg', ...)` + `loadStorage()` refresh; Name row appears/disappears/updates correctly

**Security note:**
Previous draft used `JSON.stringify(display_name)` inside `onclick="..."` — identified as unsafe (double-quote injection, unescaped `<`/`>`/`&`). Fixed by moving all string state into `_assetMap` and passing only the integer ID through the HTML attribute.

**Unchanged (confirmed):**
- Original filename, storage_key, public_url, media_type, file_size — never touched by PATCH
- R2 object — never touched
- Slug / media attachments — unaffected
- Public `/{slug}` routing — untouched
- All existing admin capabilities — untouched
- Database schema — no migration (column exists from Phase 1)

**Production deploy:**
- VPS pulled `1d11005` via `git pull origin master`
- `shadz.service` restarted; confirmed `active (running)`
- `https://shadz.io/health` → `200` `{"status":"ok"}`
- `https://shadz.io/admin` unauthenticated → `401`
- Storage Manager: Add Name / Edit Name button present on all asset cards ✓
- Blank rename clears display_name; Name row disappears on refresh ✓
- Original filename always visible ✓

**Touched:** `main.py`, `static/admin.html`
**Database:** untouched (no migration)
**Schema:** untouched
**Nginx:** untouched
**Auth:** untouched
**R2 / Media Engine upload:** untouched

---

## Page Engine v1 Phase 1 — Media Engine Display Names

**Date:** 2026-06-19
**Commit:** `4476142`
**Status:** Complete, deployed, production-verified

**Summary:**
Added optional human-readable `display_name` to media assets. Allows admin to label assets for recognition and future Page Engine use. All existing uploads and asset records remain valid; blank display_name stored as NULL.

**Schema change:**
- `media_assets.display_name VARCHAR` — nullable, added via safe `ALTER TABLE ADD COLUMN` in `_run_migrations()`
- Migration is idempotent (PRAGMA check before ALTER); skips if column already exists
- `media_assets` block wrapped in `if rows:` guard — safe if table does not exist yet (fresh environment)
- `_run_migrations()` now covers both `redirect_links` and `media_assets`

**Production DB backup created before deploy:**
- `shadz.db.backup-before-media-display-name-20260619-094628`

**Backend changes (`main.py`):**
- `MediaCompleteRequest` — added optional `display_name: str | None = None`
- `MediaAssetOut` — added `display_name: str | None = None`
- `complete_upload()` — trims display_name; blank/whitespace stored as `None`
- `list_media_assets()` — includes `display_name` in response per asset
- Presigned R2 upload endpoint (`/admin/media/upload-url`) — intentionally unchanged

**Frontend changes (`static/admin.html`):**
- Upload form: optional **Display Name** input + hint text
- `display_name` sent only in `/admin/media/complete` payload (not presign step)
- Input cleared after successful upload
- Storage Manager `buildAssetCard()`: conditional **Name** row (gold, shown only when `display_name` truthy); **File** row always visible

**Unchanged (confirmed):**
- Public `/{slug}` routing — untouched
- Page slug placeholder behavior — untouched
- All slug type policy — untouched
- Archive/restore behavior — untouched
- No Page Engine DB tables created

**Production deploy:**
- VPS pulled `4476142` via `git pull origin master`
- `shadz.service` restarted; confirmed `active (running)`
- `https://shadz.io/health` → `200` `{"status":"ok"}`
- `https://shadz.io/admin` unauthenticated → `401`
- DB migration confirmed: `PRAGMA table_info(media_assets)` shows `display_name VARCHAR` column ✓
- Upload with display_name saves correctly ✓
- Storage Manager shows Name row + File row ✓
- Existing assets (display_name NULL) show File row only — no regression ✓

**Touched:** `models.py`, `main.py`, `static/admin.html`
**SQLite migration:** additive, idempotent, auto-runs at startup
**Nginx:** untouched
**Auth:** untouched
**R2 / presign flow:** untouched

---

## Admin Hotfix — Redirect Update Phone Validation Regression

**Date:** 2026-06-16
**Commit:** `edb2c2c`
**Status:** Complete, deployed, production-verified

**Summary:**
Hotfix for a regression introduced in Phase B. The `upsert_link` backend endpoint incorrectly required `phone_number` in the existing-link update branch, causing the Admin Update Redirect function to always return "Phone number is required" even though the frontend correctly sends only `destination_url`.

**Root cause:**
In `main.py`, the update-existing-link branch contained:
```python
if payload.phone_number is None:
    raise HTTPException(status_code=400, detail="Phone number is required")
```
This unconditionally blocked any update that did not include a phone number — including legitimate redirect-only updates.

**Fix:**
Flipped the guard to only validate and write `phone_number` when it is explicitly provided by the caller:
```python
if payload.phone_number is not None:
    phone = payload.phone_number.strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number cannot be blank")
    link.phone_number = phone
```
When `phone_number` is omitted, the existing value is preserved. Blank phone still returns an error.

**Validation scope (post-fix):**
- Create new link: `phone_number` required — unchanged
- Update Redirect: `phone_number` not required — fixed
- Check Slug Info, Archive/Restore, Edit Info, Media/Page update: phone not required — unchanged

**Backend changes (`main.py`):**
- `upsert_link` update-existing branch: 6 lines replaced with 5 lines (net -1 line)

**Frontend changes:**
- None — `static/admin.html` was already correct; it sends only `destination_url` for Update Redirect

**Unchanged (confirmed):**
- Database schema: untouched — no migration
- Create flow phone validation: untouched — still enforced
- All other admin functions: archive/restore, bulk ops, CSV export, type conversion, media engine — untouched
- Nginx, shadz.service, Cloudflare/R2: untouched
- Auth behavior: untouched

**Production deploy:**
- `git pull origin master` on VPS — `edb2c2c` pulled successfully
- `shadz.service` restarted
- `https://shadz.io/health` → `200` `{"status":"ok"}`
- `https://shadz.io/admin` unauthenticated → `401`
- Admin Update Redirect with slug + URL only → success (no phone required)
- Admin Create without phone → still rejected "Phone number is required"
- All existing admin functions confirmed working

**Touched:** `main.py` only
**Database:** untouched
**Schema:** untouched
**Nginx:** untouched
**Auth:** untouched
**Frontend:** untouched

---

## Phase C — Admin CSV Export

**Date:** 2026-06-13
**Commit:** `45d2656`
**Status:** Complete, deployed, production-verified

**Summary:**
Admin CSV export for client and link data recovery. A protected `GET /admin/links/export.csv` endpoint exports all link/client records as a UTF-8 CSV attachment. An Export CSV button is placed near the top of the Admin Panel for one-click download. Designed as a recovery fallback when admin search cannot locate client information.

**Backend changes (`main.py`):**
- Added `import csv`, `import io`, `StreamingResponse` to imports
- `GET /admin/links/export.csv` added to `admin_router` — inherits existing Basic Auth dependency; no separate auth added
- Default export: all records including archived (`include_archived=True`)
- Optional `?include_archived=false` — excludes archived slugs
- Optional `?q=term` — partial LIKE match across `slug`, `phone_number`, `client_name`, `destination_url`
- Active media asset metadata resolved via batched join (not N+1)
- CSV written via `csv.QUOTE_ALL` — commas, quotes, newlines fully escaped
- `Content-Disposition: attachment; filename="shadz_links_export_YYYYMMDD_HHMMSS.csv"`
- Response: `StreamingResponse`, `text/csv; charset=utf-8`

**CSV columns:**
`slug`, `content_type`, `destination_url`, `client_name`, `phone_number`, `is_archived`, `archived_at`, `scan_count`, `created_at`, `updated_at`, `active_media_asset_id`, `media_original_filename`, `media_mime_type`, `media_file_size_bytes`, `media_storage_key`

No credentials, API keys, R2 secrets, or environment variables are included. `media_storage_key` is the bucket object path only.

**Frontend changes (`static/admin.html`):**
- Export CSV button added below the Search button in `statsSection`
- Plain `<a href="/admin/links/export.csv" download class="ghost-btn">` — browser handles Basic Auth session and triggers native file download
- No JS required; no redesign; existing style preserved

**Unchanged (confirmed):**
- Database schema: untouched — no migration, no column added or removed
- All existing admin capabilities: archive/restore, bulk archive/restore, select all/clear, type conversion, storage manager, media attach/detach — all untouched
- Redirect engine, media engine, scan tracking: untouched
- Nginx, shadz.service, Cloudflare/R2: untouched
- Auth behavior: untouched — Basic Auth dependency unchanged

**Production deploy:**
- User manually pulled `45d2656` on VPS via `git pull origin master`
- `shadz.service` restarted (`main.py` changed)
- `https://shadz.io/health` → `200` `{"status":"ok"}`
- `https://shadz.io/admin` unauthenticated → `401`
- `https://shadz.io/admin/links/export.csv` with auth → `200`, `text/csv; charset=utf-8`, `Content-Disposition` attachment confirmed
- CSV header and data rows visible; archived records included by default; active media asset fields export correctly

**Touched:** `main.py`, `static/admin.html`
**Database:** untouched
**Schema:** untouched
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched

---

## Phase B — Admin Create Validation

**Date:** 2026-06-13
**Commit:** `0268da1`
**Status:** Complete, deployed, production-verified

**Summary:**
Phone number is now required on all admin create and upsert flows. Backend trims and validates before saving. Frontend blocks submission before the request is sent.

**Backend changes (`main.py`):**
- `POST /admin/link` (`create_link`): `phone_number` is now required; `None` → 400 "Phone number is required"; stripped value empty → 400 "Phone number cannot be blank"; trimmed value saved
- `POST /admin/link/{slug}` (`upsert_link`) — update path: same validation replaces the old optional `if phone_number is not None` guard
- `POST /admin/link/{slug}` (`upsert_link`) — new-slug creation path: same validation added before object construction
- All three paths store the trimmed value only

**Frontend changes (`static/admin.html`):**
- Create form phone `<input>`: added `required` attribute
- `createLink()`: explicit `if (!phone)` guard after trim — shows "Phone number is required." and returns before fetch
- `saveInfo()`: explicit `if (!phone)` guard after trim — shows "Phone number is required." in card error area and returns before fetch

**Unchanged (confirmed):**
- Database schema: untouched — no migration, no column added or removed
- Existing Phase A rescued data: not modified, not normalised, not deleted
- Redirect engine, media engine, page engine, scan tracking: untouched
- Nginx, shadz.service, Cloudflare/R2: untouched
- All existing admin capabilities: archive/restore, bulk archive/restore, select all/clear, type conversion, storage manager, media attach/detach — all untouched

**Production deploy:**
- User manually pulled `0268da1` on VPS via `git pull origin master`
- `shadz.service` restarted (`main.py` changed)
- Local health check: `http://127.0.0.1:8000/health` → `200` `{"status":"ok"}`
- Public health check: `https://shadz.io/health` → `200` `{"status":"ok"}`
- Admin unauthenticated: `https://shadz.io/admin` → `401`
- Browser live tests passed:
  - Create link with blank phone blocked ✓
  - Create link with leading/trailing spaces saves trimmed phone ✓
  - Save Info with blank phone blocked ✓
  - Save Info with leading/trailing spaces saves trimmed phone ✓
  - Existing public slug behavior unchanged ✓

**Pending — Phase C:**
- CSV export function for admin client information recovery/search fallback
- Export button to be placed at the top of the admin panel
- CSV must include enough client/link information for manual recovery when admin search cannot find client information
- Not started

**Touched:** `main.py`, `static/admin.html`
**Database:** untouched
**Schema:** untouched
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched

---

## Phase 3 — Type Conversion v0.1

**Date:** 2026-06-03
**Commit:** `660ac44`
**Status:** Complete, deployed, production-verified

**Summary:**
URL ↔ Media type conversion for SHADZ slugs. A slug's `content_type` can now be changed between `url` and `media` without renaming or replacing the slug. The slug string is the permanent NFC identity; `content_type` controls public behavior.

**Core architecture principle confirmed:**
- `slug` = permanent NFC identity — never changes
- `content_type` = current behavior
- `destination_url` = preserved memory, even when a `url` slug converts to `media`

**Backend changes (`main.py`):**
- `LinkConvertRequest` Pydantic model — `{ "target_type": "url"|"media", "destination_url": optional }`
- `POST /admin/link/{slug}/convert` — new endpoint on `admin_router` (Basic Auth protected)
- `url → media`: sets `content_type = "media"`; preserves `destination_url` exactly as-is
- `media → url`: requires non-empty `destination_url`; blocked if active `SlugMedia` exists (must detach first); sets `content_type = "url"` and `destination_url`
- `page` conversion rejected in v0.1
- `null` / legacy `content_type` conversion rejected
- No-op response if already target type
- `scan_count`, `client_name`, `phone_number`, `notes`, `is_archived`, `archived_at` never touched

**Frontend changes (`static/admin.html`):**
- `convertRow` injected into each result card (after Archive/Restore row):
  - `url` slug: **Convert to Media** button
  - `media` slug: **Convert to URL** button
  - `page` / null: no button shown
- `convertSlugType(slug, targetType, index)` JS function:
  - `url → media`: confirm dialog with clear NFC URL / destination preservation note
  - `media → url`: `prompt()` for required destination URL; validates non-empty
  - On success: `searchSlugInfo()` refresh — card fully re-renders with new type state
  - Backend error messages (e.g. active media block) surfaced inline via `showMsg`

**Conversion rules:**

| Conversion | Precondition | Result |
|---|---|---|
| `url → media` | Any `url` slug | `content_type = "media"`, `destination_url` preserved |
| `media → url` | Active media must be detached first | `content_type = "url"`, new `destination_url` set |
| Either direction | `page` type | Rejected |
| Either direction | `null` content_type | Rejected |
| Archived slug | No restriction | Conversion allowed; archive status unchanged |

**Unchanged (confirmed):**
- Media attach endpoint: still enforces `content_type == "media"` — no guard was loosened
- Public redirect route: still branches on `content_type`, not slug prefix
- Slug naming system: no slug is renamed or regenerated
- No database migration: `content_type` column already existed and is writable
- All existing systems: Link Lifecycle Control, Media Engine, Storage Manager, Archive/Restore, Bulk Archive/Restore, Select All/Clear Selection, expired public page, Basic Auth — all working

**Production deploy:**
- VPS pulled `660ac44` via `git pull origin master` (fast-forward from `0974650`)
- `shadz.service` restarted; confirmed `active (running)`
- GET-based checks: `/` → 200, `/admin` → 401, `/health` → 200 `{"status":"ok"}`
- Browser live tests passed: URL→Media conversion, Media→URL conversion, active-media block confirmed, guard rejections confirmed

**Note — VPS DB backups (intentionally uncommitted):**
- `shadz.db.backup-before-logging-v03`
- `shadz.db.bak-phase2-20260531-103517`

**Touched:** `main.py`, `static/admin.html`
**Database:** untouched (no migration)
**Schema:** untouched
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched

---

## Patch 5.2 — Media Destination Row Fix

**Date:** 2026-06-01
**Commit:** `b388288`
**Status:** Complete, deployed, production-verified

**Problem:**
Media slugs (`media-*`) showed a Destination row with View Full / Open ↗ actions in Admin result cards. This is conceptually wrong — media slugs are controlled by active SlugMedia / MediaAsset attachment, not `destination_url`. Showing destination_url actions for media slugs caused admin confusion and would create problems before Phase 3 Type Conversion.

**Changes:**
- `buildResultCard()` return statement now conditionally includes `destinationRowHtml` only when `r.content_type !== 'media'`
- No-active-media state message enhanced: now shows "No active media attached." plus "Media destination is controlled by attached media asset."

**Behavior after patch:**

| Slug type | Destination row | Active Media panel |
|---|---|---|
| `url` | Shown — View Full + Open ↗ | Never shown |
| `page` | Shown (Page Engine does not exist yet) | Never shown |
| `media` + active media | **Hidden** | Shown |
| `media` + no active media | **Hidden** | "No active media attached." + context message |

**Frontend only:**
- `static/admin.html` — 3 lines changed (+2 / -1)
- `main.py` — untouched
- Backend endpoints — untouched
- Database — untouched
- Nginx — untouched
- Auth — untouched

**This is a pre-Phase-3 cleanup before Type Conversion. Do not implement Type Conversion until it is explicitly tasked.**

**Production deploy:**
- VPS pulled `b388288` via `git pull origin master` (from `9aa2aa6`)
- `shadz.service` restarted; brief `502 Bad Gateway` immediately after restart was startup timing only, not a code failure
- `systemctl status shadz.service` showed `active (running)`
- `journalctl` showed Uvicorn startup complete
- Port check: Uvicorn listening on `127.0.0.1:8000`
- Local health: `curl http://127.0.0.1:8000/health` → `{"status":"ok"}`
- GET-based production checks: `/` → 200, `/admin` → 401, `/health` → 200
- Browser live tests passed; user confirmed all tests passed

**Touched:** `static/admin.html` only
**Backend:** untouched
**Database:** untouched
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched

---

## Patch 5.1 — Bulk Selection UX Patch

**Date:** 2026-05-31
**Commit:** `8d4fb91`
**Status:** Complete, deployed, production-verified

**Problem:**
After Patch 5 deployed, admin had to click individual checkboxes for every result card. A client with 100+ slugs would require 100+ manual clicks to bulk archive or restore.

**Changes:**
- Added Select All button — selects all currently visible Check Slug Info result cards
- Added Clear Selection button — unticks all checkboxes and clears `selectedSlugs` Set
- Selection tools row (`#selection-tools`) appears only when search results are rendered
- Hidden automatically when: navigating home, starting a new search, no results found
- Scoped to `#searchResults .bulk-check` — never selects non-rendered database records
- Works with Show Archived off and on
- `clearSelection()` reused directly by Clear Selection button — no duplicate logic
- Existing bulk action success order preserved: `clearSelection() → await searchSlugInfo() → showMsg(...)`

**Frontend only:**
- `static/admin.html` — 17 lines added, 0 deleted
- `main.py` — untouched
- Backend endpoints — untouched
- Database — untouched
- Media Engine — untouched
- Public redirect — untouched
- Basic Auth — untouched
- Nginx — untouched

**Production deploy:**
- VPS pulled `8d4fb91` via `git pull origin master`
- `shadz.service` restarted; confirmed active/running
- `/health` returned `{"status":"ok"}`
- `/admin` returned `401` unauthenticated
- Browser live test passed:
  - Select All appears after search results render ✓
  - Clear Selection appears after search results render ✓
  - Select All selects all visible result cards ✓
  - Selected count updates correctly ✓
  - Clear Selection unticks all cards and resets bulk bar ✓
  - Works with Show Archived on and off ✓
  - Existing Bulk Archive / Bulk Restore still work ✓

**Touched:** `static/admin.html` only
**Backend:** untouched
**Database:** untouched
**Nginx:** untouched

---

## Patch 5 — Bulk Archive / Bulk Restore

**Date:** 2026-05-31
**Commit:** `44c78db`
**Status:** Complete, deployed, production-verified

**Summary:**
Bulk lifecycle control for SHADZ links. Admin can select multiple Check Slug Info result cards and archive or restore them in a single action. Designed for clients with large numbers of NFC keychains.

**Backend changes (`main.py`):**
- `BulkSlugRequest` Pydantic model — `{ "slugs": ["url-xxxxx", ...] }`
- `POST /admin/links/bulk-archive` — soft-archives selected slugs; sets `is_archived=True`, `archived_at`, `updated_at`
- `POST /admin/links/bulk-restore` — restores selected slugs; clears `is_archived` and `archived_at`
- Both endpoints on `admin_router` — protected by existing Basic Auth dependency; no per-route auth added
- Input sanitization: trim whitespace, drop empty strings, de-duplicate preserving order
- Empty slug list returns `{updated:0, skipped:0, errors:[], results:[]}` — no crash, no DB touch
- Per-slug status values — bulk-archive: `archived`, `already_archived`, `not_found`; bulk-restore: `restored`, `already_active`, `not_found`
- Single `db.commit()` after all updates — transaction-safe
- Does NOT: delete `RedirectLink` rows, delete `MediaAsset` rows, detach media, change `destination_url`, rename slug, change `content_type`

**Frontend changes (`static/admin.html`):**
- Bulk selection checkboxes (`.bulk-check`) on each result card
- `#bulk-bar` action bar — shows selected count + Bulk Archive + Bulk Restore buttons; appears when `selectedSlugs.size > 0`
- `selectedSlugs` — module-level `Set` tracking selected slug strings
- `toggleCardSelect()`, `updateBulkBar()`, `clearSelection()` — selection state helpers
- `bulkArchive()` / `bulkRestore()` — confirm → POST → `clearSelection()` → `await searchSlugInfo()` → `showMsg()`
- Both bulk buttons disabled during in-flight request — prevents double-submission
- `clearSelection()` called at start of every `searchSlugInfo()` and inside `goHome()`

**Preserved (unchanged):**
- Single Archive / Restore per card
- Show Archived toggle
- Destination View Full / Open ↗
- Edit Info
- Active Media panel
- Media Engine / Storage Manager
- Public redirect and expired page behavior (410 + no-cache)
- Basic Auth

**Production deploy:**
- VPS pulled `44c78db` via `git pull origin master`
- `shadz.service` restarted; confirmed active/running
- `/health` returned `{"status":"ok"}`
- `/admin` returned `401` unauthenticated
- Browser live test passed:
  - Admin page loads ✓
  - Checkboxes appear on result cards ✓
  - Bulk Archive works ✓
  - Show Archived shows archived slugs ✓
  - Public expired page works ✓
  - Bulk Restore works ✓
  - Public slug active again after restore ✓

**Touched:** `main.py`, `static/admin.html`
**Database:** untouched (`is_archived` and `archived_at` columns already exist from Phase 2)
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched

---

## Hotfix 4.1 — Expired Page Copy + No-Cache Headers

**Date:** 2026-05-31
**Commit:** `5a744ae`
**Status:** Complete, deployed, production-verified

**Problem:**
After restoring an archived slug, browser could still show the expired page because the 410 response had no cache headers. Expired page copy also had two copy errors: "THE SHADZ experience..." and "Contact the us...".

**Changes:**
- Expired page copy corrected to exactly:
  ```
  SHADZ EXPERIENCE HAS EXPIRED.
  CONTACT US TO REACTIVATE.
  ```
- Archived slug `410` response now sends no-cache headers:
  - `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`
  - `Pragma: no-cache`
  - `Expires: 0`
- Telegram link (`https://t.me/xshadzx`) unchanged
- Status code `410 Gone` unchanged

**Root cause of browser-cache issue:**
Pre-hotfix, the 410 response carried no cache directives. Browser/proxy cached the expired page. After restore, the backend was correct (DB `is_archived=0`, curl returned `302`) but the browser served stale 410 HTML. No-cache headers prevent this going forward.

**Production deploy:**
- VPS pulled `5a744ae` via `git pull origin master`
- `shadz.service` restarted
- Verified: archived slug returns `HTTP/1.1 410 Gone` with correct no-cache headers and corrected copy
- Verified: full cycle (archive → expired page → restore → correct redirect) works in fresh browser

**Touched:** `main.py` only
**Frontend:** untouched
**Database:** untouched
**Nginx:** untouched

---

## Phase 2 — Link Lifecycle Control

**Date:** 2026-05-31
**Commits:**
- `051490c` Add lifecycle fields for link archive support
- `29bcff3` Add expired page for archived slugs
- `d5c3041` Add admin archive restore endpoints
- `859efe2` Add admin archive controls to link search
**Status:** Complete, deployed, production-verified (with Hotfix 4.1)

**Summary:**
Soft archive/restore system for NFC slugs. Archived slugs return a branded `410 Gone` page instead of redirecting. Slugs can be restored to active without changing the slug name or any client data.

**Backend changes (`main.py`):**
- SQLite migration: `is_archived BOOLEAN`, `archived_at DATETIME` columns added to `redirect_links`
- `_expired_page_html()` — branded 410 page with Telegram contact button (`https://t.me/xshadzx`)
- `redirect_slug()` — checks `is_archived` before redirect; returns 410 + expired page if archived
- `POST /admin/link/{slug}/archive` — sets `is_archived=True`, records `archived_at` timestamp
- `POST /admin/link/{slug}/restore` — clears `is_archived=False`, clears `archived_at`
- `GET /admin/links/search` — active-only by default; `include_archived=true` param exposes archived view
- `NULL is_archived` treated as active — backward-compatible with all legacy rows

**Frontend changes (`static/admin.html`):**
- Archive / Restore button per result card in Check Slug Info
- Show Archived toggle — switches between active-only and archived result views
- Archived card state visually distinct from active

**Database migration:**
- Safe `ALTER TABLE ADD COLUMN` migration at app startup (same pattern as v0.3 client fields)
- Production DB backup created before deploy: `shadz.db.bak-phase2-20260531-103517`
- Migration confirmed successful; `redirect_links` table now has `is_archived` and `archived_at`

**Production deploy:**
- DB backed up, `git pull origin master`, `shadz.service` restarted
- Health check passed; `/admin` returned `401` unauthenticated as expected
- Single archive: ✓
- Single restore: ✓
- Show Archived toggle: ✓
- Active slugs redirect normally: ✓
- Expired public page renders correctly: ✓
- Auth, Media Engine, Storage Manager unaffected: ✓

**Touched:** `main.py`, `static/admin.html`, SQLite migration (auto-runs at startup)
**Nginx:** untouched
**Auth:** untouched
**Media Engine:** untouched
**Storage Manager:** untouched

---

## Admin UI v0.2.3 — Phase 1 Destination View Patch

**Date:** 2026-05-31
**Commit:** `d383b84`
**Status:** Complete, deployed

**Summary:**
Destination row in Check Slug Info result cards replaced with a custom interactive row.
Previously rendered as plain truncated text. Now shows View Full and Open ↗ actions.

**Changes:**
- Removed `Destination` from the generic `rows` array in `buildResultCard()`
- Split rows into `rowsBefore` (Content Type → NFC URL) and `rowsAfter` (Created → Notes)
- Custom `destinationRowHtml` inserted between the two halves — original row order preserved
- View Full: toggles an inline expanded panel showing the full `destination_url` with `word-break:break-all`
- Open ↗: opens `destination_url` in a new tab (`target="_blank" rel="noopener noreferrer"`)
- Open only renders clickable if `destination_url` matches `^https?://`; otherwise renders as a disabled `<span>`
- Empty/null `destination_url`: View Full shows "Not set"; Open is disabled
- Added `toggleDest(index)` helper with null guard (`if (!el) return`)
- No Copy button added

**Destination row order confirmed:**
Content Type → Client Name → Phone → Slug → NFC URL → **Destination** → Created → Scans → Notes

**Deployment:**
- Deployed on VPS via `git pull origin master` in `/opt/shadz-os/Desktop/shadz-os`
- No service restart required (static file change only)
- No Nginx changes required

**Touched:** `static/admin.html` only
**Backend:** untouched
**Database:** untouched
**Auth:** untouched
**Media logic:** untouched
**Nginx:** untouched

---

## 2026-05-28 — Add Claude Code operating rules

**Status:** Complete

**Summary:**
Added root-level `CLAUDE.md` containing the SHADZ Claude Code operating rules.

The rules enforce:
- production safety first
- think before coding
- simplicity first
- surgical changes
- goal-driven execution
- read before write
- checkpointing
- codebase convention matching
- fail-loud reporting

This is documentation/workflow only. No runtime code, backend, frontend, database, Nginx, service, or deployment changes.

**Touched:** `CLAUDE.md` (new), `docs/CLAUDE_WORKFLOW.md`, `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md`
**Backend:** untouched
**Frontend:** untouched
**Endpoints:** untouched

---

## Front Page v0.1.2 — Hero Logo Core Patch

**Date:** 2026-05-10
**Status:** Complete, deployed, mobile-approved

**Summary:**
Replaced the CSS circular artifact in the hero section with two separate production assets: a floating animated core emblem and a stable SHADZ wordmark. Hero copy and CTA are unchanged.

**Changes:**
- Removed old CSS `.hero-wordmark` large "SHADZ" text from hero copy column
- Added `<img class="logo-img">` — `static/assets/shadz-logo-core.png` (transparent PNG, floating/animated)
- Added `<img class="wordmark-img">` — `static/assets/shadz-wordmark.png` (transparent PNG, stable/static)
- Core emblem: CSS float keyframe + subtle JS cursor tilt on hover (`hover: hover` gated)
- Wordmark: no float animation; `scaleY(1.12)` for stronger vertical presence; tightly grouped below core via negative `margin-top` calc
- Introduced `--logo-size` CSS custom property (decoupled from `--artifact-size` used by scan rings)
- Tuned all responsive breakpoints: desktop 280px core / 360px wordmark, tablet 195px / 285px, 540px 162px / 240px, 380px 130px / 195px
- Reduced mobile `.hero-inner` gap from `3rem` to `1.5rem` to tighten wordmark-to-eyebrow spacing
- `prefers-reduced-motion` gates all CSS animations; `hover: hover` gates JS tilt
- Mobile hero layout approved (logo above copy, single-column stack)

**Assets added:**
- `static/assets/shadz-logo-core.png`
- `static/assets/shadz-wordmark.png`

**Production deploy note:**
Nginx on VPS required a new `location ^~ /static/` block to serve the hero assets directly. Added manually to the HTTPS server block:
```
location ^~ /static/ {
    alias /opt/shadz-os/Desktop/shadz-os/static/;
    try_files $uri =404;
    access_log off;
    expires 7d;
}
```
Both assets confirmed live — `/static/assets/shadz-logo-core.png` and `/static/assets/shadz-wordmark.png` return `200`.

**Touched:** `static/index.html`, `static/assets/` (new files only), Nginx config (VPS only, manual)
**Backend:** untouched
**Admin:** untouched
**Endpoints:** untouched

---

## Front Page v0.1.1 — CTA Contact Patch

**Date:** 2026-05-07
**Commit:** `23aba99`
**Status:** Complete, deployed, browser-verified

**Summary:**
Final front page CTA button linked to Telegram contact. Previously pointed to `#concept` (a page anchor), which prevented potential clients from making contact.

**Changes:**
- Final CTA `.btn-primary` inside `#cta` section: `href="#concept"` → `href="https://t.me/xshadzx"` with `target="_blank" rel="noopener noreferrer"`
- Hero CTA (`class="hero-cta"`) remains `href="#cta"` — scrolls visitors to the final CTA section as intended
- Navbar links unchanged

**Verification:**
- Front page responds `200`
- Served HTML contains `t.me/xshadzx`
- `/health` returns `{"status":"ok"}`
- `/admin` still requires authentication
- Browser test confirmed final CTA opens Telegram correctly

**Touched:** `static/index.html` only
**Backend:** untouched
**Endpoints:** untouched

---

## v0.2.2 — Admin UI Result Card Redesign

**Date:** 2026-05-07
**Commit:** `dcdf879`
**Status:** Complete, deployed, live-tested

**Summary:**
Result cards in Check Slug Info redesigned into premium equal-height 2-column command modules.

**Changes:**
- Desktop/iPad: 2 cards per row (was 3)
- Mobile breakpoint moved to 700px (was 600px)
- `@media (max-width: 900px)` fallback removed
- `align-items: stretch` on grid for equal-height rows
- `#searchResults .stats-box` scoped to flex column — Storage Manager unaffected
- `.card-body` flex-expands data rows, pins action zone to card bottom
- `#searchResults .value-overflow` uses single-line ellipsis truncation (no more break-all wrapping)
- Active Media panel compacted: Asset ID, Type, truncated filename, `Open Media ↗` link — raw URL row removed
- Detach Media and Edit Info unchanged

**Touched:** `static/admin.html` only
**Backend:** untouched
**Endpoints:** untouched

---

## v0.2.1 — Admin UI Result Grid Layout

**Date:** 2026-05-07
**Commit:** `89a6a28`
**Status:** Functional but visually unsatisfactory — superseded by v0.2.2

**Summary:**
Check Slug Info and Storage Manager result cards converted to a responsive CSS grid.
Desktop 3 columns, tablet 2, mobile 1.
Live-tested and working but the 3-column desktop layout felt cramped and ugly.
Unequal card heights caused by Active Media blocks were unacceptable.
Superseded by v0.2.2.

**Touched:** `static/admin.html` only

---

## v0.2 Phase 1 — Admin Dashboard UI Shell

**Commit:** `83428eb`
**Status:** Complete

**Summary:**
Admin home screen reorganized into two labeled module groups: Link Engine and Media Engine.
CSS utility classes added for reuse across panels.

**Touched:** `static/admin.html` only
**Backend:** untouched

---

## v0.1 — SHADZ Front Page

**Commit:** `c7f91bf`
**Status:** Complete

**Summary:**
Live at https://shadz.io/
FastAPI `GET /` serves `static/index.html`.
Nginx HTTPS server block proxies root to FastAPI.

**Brand direction:**
- Cinematic black-gold
- Premium private system
- Physical-digital experience company — not just NFC keychains

**Hero copy:** `SHADZ / Touch to Unlock. / Start with one touch.`

**Touched:** `static/index.html`, Nginx config, `main.py` (`GET /` route)

---

## Media Engine v0.1.2 — Storage Manager Cleanup + Detach Patch

**Commit:** `196ba55`
**Status:** Complete

**Summary:**
Full media lifecycle now operational: Upload → Attach → Render → Detach → Safe Delete.

- Storage Manager hides deleted assets by default
- Check Slug Info shows Active Media panel
- Detach Media works; slug shows "Media not ready yet" after detach
- Active slug usage count updates correctly

**Touched:** `main.py`, `static/admin.html`

---

## Media Engine v0.1.1 — Delete Safety Patch

**Commit:** `6d4dec9`
**Status:** Complete

**Summary:**
Deleting a `MediaAsset` that is still linked to one or more active slugs is blocked.
Clear error returned instead of silently breaking active media slugs.

**Touched:** `main.py`

---

## Media Engine v0.1 — Core Upload + Attach + Render

**Status:** Complete

**Summary:**
- Admin media upload flow (presigned R2 PUT + confirm step)
- Storage Manager browse
- Upload Media Asset
- Attach Media to Slug
- Public media slug render

**Touched:** `main.py`, `static/admin.html`, R2 bucket config

---

## Naming + Logging System v0.3

**Status:** Complete

**Summary:**
- Auto-generated slug format: `{content_type}-{randomID}`
- Content types: `url`, `media`, `page`
- Admin can create links with client name, phone, notes, destination URL
- Check Slug Info searches by phone/contact
- One client can have multiple slug records
- Edit Info updates client name, phone, notes (separate from redirect URL)
- Update Redirect Link kept separate from Edit Info
- Backend validates `content_type`
- Legacy slugs preserved
- SQLite migration added client logging fields safely

**Touched:** `main.py`, `static/admin.html`, SQLite migration

---

## Redirect Engine v0.1

**Status:** Complete

**Summary:**
- Dynamic slug redirect system live
- `/{slug}` resolves through FastAPI to destination
- `scan_count` increments on each hit
- Old hardcoded Nginx redirects removed

**Touched:** `main.py`, Nginx config
