# SHADZ — Changelog

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
| `url → media` | Any active `url` slug | `content_type = "media"`, `destination_url` preserved |
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
