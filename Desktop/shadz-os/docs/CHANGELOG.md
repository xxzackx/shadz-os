# SHADZ — Changelog

---

## Page Engine v1 Phase 3C — Public Page Rendering

**Date:** 2026-06-26
**Commit:** (pending deploy approval)
**Status:** Complete, locally verified

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
