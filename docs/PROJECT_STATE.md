# SHADZ — Project State

## Mission

SHADZ is a physical-digital private system brand.
NFC / physical touch becomes a controllable digital command system.
Not just NFC keychains — the platform is the command layer between physical objects and digital destinations.

---

## Architecture

| Layer | Technology |
|---|---|
| Application | FastAPI + Uvicorn |
| Process manager | systemd (`shadz.service`) |
| Reverse proxy | Nginx |
| Database | SQLite |
| Media storage | Cloudflare R2 |
| R2 bucket | `shadz-media` |
| R2 public domain | `media.shadz.io` |

**Uvicorn bind:**
```
/usr/local/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

Nginx proxies HTTPS traffic to `127.0.0.1:8000`.

---

## VPS

- Project path: `/opt/shadz-os`
- systemd service: `shadz.service`
- `.env` holds `TELEGRAM_BOT_TOKEN` and `TELEGRAM_WEBHOOK_SECRET` (Phase T1B, added 2026-07-02) — values not recorded in docs; webhook route fails closed if `TELEGRAM_WEBHOOK_SECRET` is unset

Useful commands:
```bash
sudo systemctl restart shadz.service
sudo systemctl status shadz.service
sudo journalctl -u shadz.service -n 50
```

---

## Live URLs

| Purpose | URL |
|---|---|
| Main site | https://shadz.io/ |
| Admin UI | https://shadz.io/admin |
| Health check | https://shadz.io/health |
| Media domain | https://media.shadz.io |

---

## Redirect Flow

NFC chips store a SHADZ slug URL, not the final destination URL.

```
NFC chip → shadz.io/{slug} → Nginx → FastAPI → DB lookup → destination redirect
```

- Scan count increments on each redirect hit.
- Slug format: `{content_type}-{randomID}` (e.g. `url-a1b2c3`, `media-x9y8z7`).
- Current content types: `url`, `media`, `page`.

---

## Admin System

- UI: `static/admin.html` (single-file, no build step)
- Auth: HTTP Basic Auth via browser popup
- Unauthenticated requests to `/admin` must return `401`
- No logout button yet — browser handles session
- Future: proper UI login/logout system

**Admin capabilities:**
- Create new SHADZ links (slug + client info)
- Update redirect destination for a slug
- Check Slug Info by phone/contact number
  - Destination row: View Full (inline expand) + Open ↗ (new tab) — `url` and `page` slugs only (Patch 5.2)
  - Archive slug (soft archive, recoverable) — Phase 2
  - Restore slug (clears archive state) — Phase 2
  - Show Archived toggle (active-only default; opt-in archived view) — Phase 2
  - Bulk Archive selected slugs — Patch 5
  - Bulk Restore selected slugs — Patch 5
  - Select All Visible result cards — Patch 5.1
  - Clear Selection — Patch 5.1
- Edit client info (name, phone, notes)
- Upload media assets to R2 (optional display name supported — Phase 1)
- Attach / detach media assets to media slugs
- Storage Manager (browse all assets; rename / add display name — Phase 1B)
- Convert URL ↔ Media type — Phase 3 v0.1
- Export CSV — download all link/client records as CSV — Phase C
- Page Engine admin routes (Phase 3A, `c6c5a15`) — create/update pages; attach/detach pages to page slugs; all backend-only
- Page Engine admin UI (Phase 3B, `a57fff7`) — Module C in admin panel; Create Page, Edit Page (partial-update), Attach / Detach; wired to Phase 3A backend routes
- Page Engine admin JSON helper / template guidance (Phase 3D, `357a85e`) — template guide shows expected content_json fields per template; Fill sample JSON button; inline JSON validation hint on textarea blur
- Page Engine admin UX polish (Phase 4K, `2e54262`/`825bab6`/`6a18965`, deployed 2026-07-14) — Create/Edit Page result panels reset on navigation; Edit Page fields clear only after a successful update (failed/error requests preserve entered values); Check Slug cards for `page`-type slugs get a "Manage Page Attachment" shortcut that opens Attach/Detach and prefills both slug fields (Page ID left blank, no auto-submit); Attach/Detach fields reset when leaving the section; see Completed milestones below
- Check Slug Page Optimisation (Phase 4Ka, `38e476f`, deployed 2026-07-14) — the "Manage Page Attachment" shortcut on `page`-type Check Slug cards now expands an inline Attach/Detach panel at the bottom of the selected card instead of navigating to the standalone `pageAttachSection`; no desktop width shift; only one inline panel open at a time; see Completed milestones below
- Bot Engine admin routes (Phase T1, `28559a3`) — `POST /admin/bot/clients`, `GET /admin/bot/clients`, `POST/DELETE /admin/bot/clients/{id}/slugs`, `POST /admin/bot/clients/{id}/regenerate-code`, `PATCH /admin/bot/clients/{id}`; all behind existing Basic Auth
- Bot Engine admin UI (Phase T1D, `67fad4e`) — Module D in admin panel; create bot client, view access code, assign/unassign slug, client list with refresh; wired to Phase T1 backend routes
- Bot Engine admin UI polish (Phase T1E, `e74665b` + `23d9934`, deployed 2026-07-04) — `static/admin.html` only, frontend-only polish on top of T1D; no new routes, no backend/DB/runtime changes; see Completed milestones below
- Bot Client deactivate/reactivate/delete controls (Phase T1G, `df4d384`, deployed 2026-07-05) — Admin UI toggle + delete buttons on each Bot Client card; new `DELETE /admin/bot/clients/{id}` route; see Completed milestones below
- Check Slug → Bot Client assign shortcut (Phase T1I, `57b2229`, deployed 2026-07-06) — each Check Slug result card gets an "Assign to Bot Client" control that reuses the existing slug-assignment route; see Completed milestones below
- Regenerate Access Code UI (Phase T1J, `9b13c23`, deployed 2026-07-08) — each Bot Client card gets a confirmation-gated "Regenerate Access Code" button that reuses the existing `POST /admin/bot/clients/{id}/regenerate-code` route; see Completed milestones below
- Bot test data cleanup controls (Phase T1K, `6523079`, deployed 2026-07-08) — admin-only bulk cleanup: new `POST /admin/bot/clients/bulk-delete` route + Bot Client card "Select for Cleanup" checkbox, Select All / Clear Selection, and "Delete Selected (Cleanup)" bulk bar; removes only `BotClient` rows and their `BotClientSlug` assignment rows — slugs, media, and scan data are never touched; see Completed milestones below
- Phase T1L Final Audit / Closure (docs-only, 2026-07-08) — confirmed Telegram Bot Self-Service v1 route wiring, admin protection, webhook secret protection, bot client lifecycle, slug assignment safety, URL/media replacement safety, Admin UI lifecycle controls, and T1K cleanup controls all remain intact; no runtime/backend/frontend/DB/schema/deployment changes required; see Completed milestones below

**Admin UI version:** Phase T1K `6523079` — Bot test data cleanup controls (deployed 2026-07-08). Previous: Phase T1J `9b13c23` — Regenerate Access Code UI (deployed 2026-07-08). Previous: Phase T1I `57b2229` — Check Slug → Bot Client assign shortcut (deployed 2026-07-06). Previous: Phase T1G `df4d384` — Bot Client deactivate/reactivate/delete controls (deployed 2026-07-05). Previous: Phase T1E `23d9934` Telegram Bot Clients admin UI polish. Phase T1D `67fad4e` Telegram Bot Clients admin UI. Phase 3D `357a85e` Page Engine JSON helper guidance. Bot Engine Phase T1 (`28559a3`) added backend routes only. Phase 3B `a57fff7` Page Engine admin UI. Phase 3C (`165c0d3`) added public page rendering — no admin UI change. Phase 1B `1d11005` media asset rename. Phase C `45d2656` CSV export.

---

## Telegram Bot Runtime (Phase T1B — deployed 2026-07-02; Phase T1C — deployed 2026-07-02; Phase T1F — deployed 2026-07-04; Phase T1G — deployed 2026-07-05)

- Public webhook: `POST /bot/telegram/webhook` — registered in `main.py` via `register_bot_webhook_routes(app)`, before the `/{slug}` catch-all
- No Basic Auth (Telegram cannot supply it); protected instead by a mandatory shared-secret header check — `X-Telegram-Bot-Api-Secret-Token` must match `TELEGRAM_WEBHOOK_SECRET`
  - Secret not configured on server → `503`
  - Missing/wrong header → `401`
  - Correct header → `200 {"ok": true}`
- Customer flow (via Telegram chat): enter `access_code` (from Bot Engine admin, Phase T1) → see assigned `url`/`media` slugs → select a slug
  - `url` slug: view current `destination_url` → submit replacement → Link Safety Guard blocks SHADZ/internal destinations before confirmation (T1F, `a7510e1`) → confirm → `redirect_links.destination_url` updated (T1B)
  - `media` slug: send a replacement photo/document/video/GIF → validated against the existing `ALLOWED_MEDIA_TYPES` mime allowlist (`media_admin.py`) → downloaded from Telegram via `getFile` → uploaded server-side to R2 → new `MediaAsset` created → previous active `SlugMedia` deactivated → new active `SlugMedia` created (T1C, `d126dbc`)
- Conversation state (`_SESSIONS`) and update-id dedup (`_SEEN_UPDATE_IDS`) are in-memory only — acceptable for a single Uvicorn process (no `--workers`), lost on service restart (owner-approved for T1B)
- Every authenticated state transition (not just login) re-checks `BotClient.is_active` (Phase T1G, `df4d384`) — a client deactivated mid-conversation is kicked back to the access-code prompt immediately instead of retaining access until session expiry or service restart
- Outbound Telegram messages sent via `httpx.AsyncClient` (`_send_message`); fails safe (logs, does not crash) if `TELEGRAM_BOT_TOKEN` is unset
- Nginx: new `location` block proxies `/bot/telegram/webhook` to `127.0.0.1:8000`, forwarding `X-Telegram-Bot-Api-Secret-Token`; added alongside existing `/`, `/admin`, `/health`, `/static/`, and slug routes
- `requirements.txt`: `httpx==0.27.2` added (T1B)
- `.env.example`: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` documented (no real values in repo)
- No DB schema change — reuses `bot_clients` / `bot_client_slugs` from Phase T1, and `media_assets` / `slug_media` from Media Engine v0.1
- Telegram `setWebhook` pointed at `https://shadz.io/bot/telegram/webhook`; `getWebhookInfo` confirmed no pending updates, no last error
- **T1C reuse note:** `bot_runtime.py` imports `ALLOWED_MEDIA_TYPES`, `_get_r2_client`, `_make_storage_key`, `_make_public_url` directly from `media_admin.py` to avoid duplicating R2/upload logic. This is intentional reuse, not a refactor — `media_admin.py` itself was not modified. Future cleanup debt: if a third module needs these helpers, extract them into a shared media storage module; not done in T1C to keep the change surgical.
- **Admin UI note:** Phase T1C live testing used the existing `/admin/bot/*` API routes directly (create client, assign slug, confirm, remove assignment, deactivate) — no new routes, no UI added at the time. Phase T1D (`67fad4e`, deployed 2026-07-04) added a basic Admin UI for Bot Client management in `static/admin.html`; Phase T1E (`e74665b` + `23d9934`, deployed 2026-07-04) polished that same UI (stale-state fix, Assign Slug auto-fill, Telegram link status, readable validation error) — no new routes — see Completed milestones below.
- **Link Safety Guard (Phase T1F, `a7510e1`, deployed 2026-07-04):** `bot_runtime.py` only — the `url` slug replacement flow now blocks destinations pointing back at SHADZ (`shadz.io`, `www.shadz.io`) or internal/local addresses (`localhost`, `127.0.0.1`, `0.0.0.0`), plus any non-`http`/`https` scheme or missing/invalid scheme, before the destination reaches confirmation/save. Normal external URLs are unaffected. Media replacement flow, admin UI, routes, and DB schema untouched — see Completed milestones below.
- **Bot Client Deactivate/Delete Control (Phase T1G, `df4d384`, deployed 2026-07-05):** `bot_admin.py`, `bot_runtime.py`, `static/admin.html` — new `DELETE /admin/bot/clients/{client_id}` route (removes only the `BotClient` row and its `BotClientSlug` assignment rows; `RedirectLink` slugs, media, and history are never touched); Admin UI gets Deactivate/Activate toggle and Delete buttons on each Bot Client card; `bot_runtime.py` now re-checks `is_active` on every authenticated action, not just login, so deactivation takes effect immediately even for an already-logged-in Telegram session. Existing slug assignments are preserved on deactivation and restored on reactivation. No DB migration (`is_active` column already existed). See Completed milestones below.

---

## Database Schema — Live State

### `redirect_links`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `slug` | VARCHAR | unique, indexed |
| `destination_url` | VARCHAR | not null |
| `scan_count` | INTEGER | default 0 |
| `content_type` | VARCHAR | url / media / page; nullable (legacy rows) |
| `client_name` | VARCHAR | nullable |
| `phone_number` | VARCHAR | indexed; nullable |
| `notes` | TEXT | nullable |
| `is_archived` | BOOLEAN | nullable — `NULL` treated as active (added Phase 2) |
| `archived_at` | DATETIME | nullable — set on archive, cleared on restore (added Phase 2) |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

### `media_assets`

One row per uploaded R2 file. Soft-deleted via `is_deleted=True`. Never auto-removed from R2.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `media_type` | VARCHAR | video / image / audio / gif |
| `storage_provider` | VARCHAR | `r2` |
| `storage_key` | VARCHAR | path inside R2 bucket |
| `public_url` | VARCHAR | `media.shadz.io/...` |
| `original_filename` | VARCHAR | original upload name — never changed |
| `mime_type` | VARCHAR | |
| `file_size` | BIGINT | bytes |
| `display_name` | VARCHAR | nullable; human-readable label (added Phase 1) |
| `is_deleted` | BOOLEAN | soft-delete flag |
| `created_at` | DATETIME | |
| `deleted_at` | DATETIME | nullable |

### `slug_media`

Join between `redirect_links.slug` and `media_assets.id`. History preserved; only one row per slug has `is_active=True`.

### `pages` _(added Page Engine v1 Phase 2)_

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `title` | VARCHAR | not null |
| `template_type` | VARCHAR | not null; one of `invitation`, `brand_product`, `child_safety` |
| `status` | VARCHAR | not null; default `draft`; one of `draft`, `ready`, `archived` |
| `content_json` | TEXT | nullable; unstructured for now |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |
| `archived_at` | DATETIME | nullable |

### `page_slug_attachments` _(added Page Engine v1 Phase 2)_

Join between `pages.id` and `redirect_links.slug`. One page may attach to many slugs. Only one active attachment per slug enforced by partial unique index `idx_page_slug_one_active`.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `page_id` | INTEGER | FK → `pages.id`; indexed |
| `slug` | VARCHAR | FK → `redirect_links.slug`; indexed |
| `is_active` | BOOLEAN | not null |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

**Partial unique index:** `idx_page_slug_one_active ON page_slug_attachments(slug) WHERE is_active = 1`

**FK note:** `PRAGMA foreign_keys=ON` is not enabled — FK declarations are ORM metadata only, same as `slug_media`. Application-layer enforcement added in Phase 3A (slug existence + content_type validation in attach route).

### `bot_clients` _(added Phase T1)_

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `client_name` | VARCHAR | not null |
| `access_code` | VARCHAR | not null; unique; indexed; plain text by owner decision |
| `telegram_user_id` | VARCHAR | nullable — for future Telegram binding |
| `telegram_username` | VARCHAR | nullable |
| `is_active` | BOOLEAN | not null; default `True` |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

Access code format: 6 chars, A-Z + 0-9, ≥1 letter and ≥1 digit, generated with `secrets.choice`. No `SHADZ-` prefix.

### `bot_client_slugs` _(added Phase T1)_

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `bot_client_id` | INTEGER | not null; indexed; FK → `bot_clients.id` (ORM metadata only) |
| `slug` | VARCHAR | not null; unique; indexed; FK → `redirect_links.slug` (ORM metadata only) |
| `created_at` | DATETIME | |

UNIQUE on `slug` enforces one-slug-per-bot-client at DB level. FK enforcement relies on application-layer validation, consistent with rest of schema (`PRAGMA foreign_keys=ON` not enabled). Only `url` and `media` slugs may be assigned — `page` slugs rejected. Archived slugs cannot be assigned. Deactivating a bot client does NOT cascade to delete assignments.

Tables created by `Base.metadata.create_all(bind=engine)` on first startup after deploy — no `_run_migrations()` change needed.

### `nfc_records` / `scan_logs`

Legacy NFC system. Unchanged since v0.1.

---

## Media System

- Upload flow: Admin → presigned R2 PUT → confirm to FastAPI → `MediaAsset` row created
- Optional `display_name` saved on upload; blank/whitespace stored as NULL (Phase 1)
- Rename flow: Admin can Add Name / Edit Name on any asset in Storage Manager via `PATCH /admin/media/assets/{id}` (Phase 1B)
- Attach flow: Admin links `MediaAsset` to a `media` slug
- Render flow: `/{slug}` for media type serves the attached asset
- Detach: unlinks asset from slug; slug shows "Media not ready yet"
- Delete safety: deleting a `MediaAsset` still linked to active slugs is blocked
- `_run_migrations()` covers both `redirect_links` and `media_assets` tables (Phase 1)

---

## Auth State

- Basic Auth is live and working
- Visually ugly (browser native popup)
- Acceptable for current private admin use
- Future hardening: UI login/logout, session management, role-based access

---

## Safe Operating Rules

- Do NOT use `curl -I` or HEAD-method requests to verify SHADZ routes. FastAPI routes currently only allow GET — HEAD returns `405 Method Not Allowed`. Use GET-based checks: `curl -s -o /dev/null -w "%{http_code}\n" <url>`
- URL content type is allowed to point at any destination including `media.shadz.io` for now — only admin can edit links
- Do not add backend validation blocking URL type from pointing to `media.shadz.io` until: client portal, staff roles, multi-admin, or API-based link creation is added
- Do not modify `main.py` unless the task explicitly requires backend changes
- Do not modify database models unless the task explicitly requires a migration
- Nginx config and systemd config should not be touched without a specific infra task
- Always verify `/admin` returns 401 unauthenticated after any auth-adjacent change
- `HEAD` or unsupported HTTP methods returning 405 is expected behavior, not a bug
- On VPS, use `python3` not `python` — `python` is not in PATH
- After `sudo systemctl restart shadz.service`, wait before curl checks — an immediate check may briefly show `502 Bad Gateway` while Uvicorn is still starting; use `sleep 5` or a retry loop before hitting Nginx endpoints
- After `sudo systemctl restart shadz.service`, do not run production (`https://shadz.io/...`) health checks immediately — poll local readiness first (`http://127.0.0.1:8000/health`), since Uvicorn may take a few seconds after systemd reports the service started. Confirmed pattern (added Phase T1J, 2026-07-08):
  ```bash
  for i in {1..15}; do
    if curl -s http://127.0.0.1:8000/health | grep -q '"status":"ok"'; then
      echo "local app ready"
      break
    fi
    echo "waiting for app... $i"
    sleep 1
  done
  ```
  Only run public `https://shadz.io/health` / `/admin` checks after the local loop reports ready — this avoids false `502` alarms.

---

## Known Issues

| Issue | Status |
|---|---|
| Basic Auth popup is ugly | Accepted, deferred |
| No clean logout / session flow | Deferred |
| No analytics / scan tracking chart | Planned |
| No role-based access control | Deferred until multi-admin needed |

---

## Front Page Hero State

**SHADZ Front Page v0.1.2 — Hero Logo Core Patch** — Deployed

- Hero visual replaced with final S-core emblem (`static/assets/shadz-logo-core.png`) + separate SHADZ wordmark layer (`static/assets/shadz-wordmark.png`)
- Core is animated/floating (CSS keyframe + subtle JS cursor tilt on hover)
- Wordmark is stable/static — no float animation
- Assets are true transparent PNGs stored under `static/assets/`
- Front page remains lightweight CSS + vanilla JS — no Three.js or heavy dependencies
- Mobile-first layout approved: logo stacks above hero copy, wordmark tightly grouped below core
- Hero assets served from `/static/assets/` — both return `200` in production
- Production Nginx has a `location ^~ /static/` alias route pointing to `/opt/shadz-os/static/` (updated Phase T1A)
- Backend / admin / redirect / media systems unchanged

---

## DevOps / Claude Code Rules

A root-level `CLAUDE.md` file now defines the mandatory operating rules for Claude Code in this project.

Purpose:
- reduce implementation mistakes
- avoid overengineering
- enforce read-before-write
- enforce surgical changes
- require verification before claiming completion
- prevent silent skipped tests or hidden uncertainty
- protect the live SHADZ production system

---

## Execution Context / Guardrails

This section exists to give Claude Code a compressed snapshot of current project state and active constraints. It is not a roadmap or task queue. Do not infer permission to start future work from anything written here.

### Completed milestones

- Link Lifecycle Control (Phase 2) — archive, restore, 410 expired page, no-cache headers — complete
- Bulk Archive / Bulk Restore (Patch 5) — complete
- Select All / Clear Selection (Patch 5.1) — complete
- Media Destination Row Fix (Patch 5.2, `b388288`, deployed 2026-06-01) — Admin result cards now show Destination row only for `url` and `page` slugs, not `media` slugs
- Type Conversion v0.1 (Phase 3, `660ac44`, deployed 2026-06-03) — URL ↔ Media conversion live; slug identity permanent, content_type controls behavior
- Admin Create Validation (Phase B, `0268da1`, deployed 2026-06-13) — phone_number required when creating new links/client records; trimmed before save; backend rejects missing/blank on create; existing-link redirect updates do not require phone after hotfix `edb2c2c`
- Admin CSV Export (Phase C, `45d2656`, deployed 2026-06-13) — protected GET /admin/links/export.csv; default exports all records including archived; optional include_archived and q filters; CSV includes slug/client/link/media/admin review fields; Export CSV button near top of admin panel; no schema migration
- Admin Hotfix — Redirect Update Phone Regression (`edb2c2c`, deployed 2026-06-16) — `upsert_link` update branch no longer requires phone_number; phone preserved if not provided; create flow still requires phone; no frontend change; no schema migration
- Page Engine v1 Phase 1 — Media Engine Display Names (`4476142`, deployed 2026-06-19) — nullable `display_name` column added to `media_assets`; safe additive migration; upload form + Storage Manager updated; presign endpoint unchanged; no Page Engine DB tables
- Page Engine v1 Phase 1B — Media Asset Rename (`1d11005`, deployed 2026-06-19) — `PATCH /admin/media/assets/{id}` endpoint; Storage Manager Add Name / Edit Name action; `_assetMap` pattern prevents XSS via HTML attributes; only `display_name` writable; all other asset fields and R2 object unchanged
- Page Engine v1 Phase 2 — DB Foundation (`e37a56c`, deployed 2026-06-20) — `pages` + `page_slug_attachments` tables; `PAGE_TEMPLATE_TYPES` + `PAGE_STATUSES` constants; idempotent migration guards; partial unique index `idx_page_slug_one_active`; no routes, no UI, no public rendering; DB backup `shadz.db.backup-before-page-engine-phase2-20260620-195630`
- Page Engine v1 Phase 3A — Admin Backend Routes (`c6c5a15`, deployed 2026-06-20) — page create/update/attach/detach admin routes; safety helpers; Pydantic schemas; all routes behind existing Basic Auth; re-attach deactivates old active attachment and preserves history; no public rendering; no DB migration; DB backup `shadz.db.backup-before-page-engine-phase3a-20260620-211430`
- Page Engine v1 Phase 3B — Admin UI (`a57fff7`, deployed 2026-06-25) — `static/admin.html` only; Module C Page Engine on home screen; Create Page, Edit Page (partial-update), Attach/Detach sections; four JS functions wired to Phase 3A routes; no backend changes; no new routes; DB backup `shadz.db.backup-before-page-engine-phase3b-20260625-184943`
- Page Engine v1 Phase 3C — Public Page Rendering (`165c0d3`, deployed 2026-06-26) — `main.py` only; `_render_page_html()` renders `invitation`, `brand_product`, `child_safety` templates; page slug with active attachment → 200 HTML; no active attachment → 404; archived → 410 unchanged; all user text HTML-escaped; visual design acceptable for testing, not yet client-facing polish
- Page Engine v1 Phase 3D — Admin JSON Helper (`357a85e`, deployed 2026-06-26) — `static/admin.html` only; template guide with field list + Fill sample JSON button; inline JSON validation (valid/invalid hint on blur); null-guarded JS functions; no backend changes; no DB migration; no renderer change
- Page Engine v1 Phase 4A — Renderer Extraction (`e3965f5`, deployed 2026-06-26) — `_render_page_html()` moved from `main.py` into new `page_renderer.py`; `import html` and `import json` moved with it; `main.py` imports it via `from page_renderer import _render_page_html`; refactor-only, no behavior change, no DB migration, no admin UI change, no route change
- Page Engine v1 Phase 4B — Admin Extraction (`054b4b6`, deployed 2026-06-27) — 5 Page Engine Pydantic schemas, 4 helper functions, and 6 admin route handlers moved from `main.py` into new `page_admin.py`; `register_page_admin_routes(admin_router)` wires routes back; `main.py` reduced by ~386 lines; refactor-only, no behavior change, no DB migration, no admin UI change, no route change; browser live-tested: Create/Edit/Attach/Detach/render all confirmed ✓
- Page Engine v1 Phase 4C — Dead Code Removal (`832a753`, 2026-06-27) — `_page_placeholder_html` removed from `main.py` (orphaned in Phase 3C, confirmed no callers anywhere in codebase); `redirect_slug` docstring corrected from stale "placeholder 'Coming soon'" to accurate "renders active attached page via Page Engine (404 if none attached)"; runtime-cleanup only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; `main.py` reduced from 1720 to 1703 lines
- Page Engine v1 Phase 4D — Public Page Handler Extraction (`d502819`, deployed 2026-06-27) — public page block extracted from `redirect_slug` into new `page_public.py` (`serve_public_page`); shared attachment query moved into new `page_queries.py` (`get_active_page_attachment`); `page_public.py` imports only from `page_queries`/`page_renderer` — no admin coupling; `page_admin.py` updated to use `page_queries`; `main.py` calls `serve_public_page(slug, db)`; refactor-only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; browser live-tested: Admin ✓, page slug ✓, URL slug ✓, media slug ✓
- Page Engine v1 Phase 4E — Public Link Handler Extraction (`f32ec27`, deployed 2026-06-28) — 3 HTML generators (`_expired_page_html`, `_media_page_html`, `_media_not_ready_html`) and media dispatch logic moved from `main.py` into new `link_public.py` (`expired_page_response`, `serve_public_media`); `@app.get("/{slug}")` route decorator kept in `main.py` for route-order safety; `HTMLResponse` import removed from `main.py`; refactor-only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; browser live-tested: Admin ✓, URL slug ✓, media slug ✓, page slug ✓, archived 410 ✓
- Page Engine v1 Phase 4F — Media Engine Admin Extraction (`f490ae8`, deployed 2026-06-28) — 8 Media Engine admin route handlers, 9 Pydantic schemas, and 5 R2 helper functions/constants moved from `main.py` into new `media_admin.py`; `register_media_admin_routes(admin_router)` wires routes back; `boto3`, `botocore`, and `func` imports removed from `main.py`; refactor-only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; browser live-tested: Admin ✓, media upload ✓, media attach/detach ✓, Storage Manager ✓
- Page Engine v1 Phase 4G — Link Engine Admin Extraction (`68e9d0e`, deployed 2026-06-28) — 8 Link Engine Pydantic schemas, 3 slug helpers/constants, and 10 admin route handlers moved from `main.py` into new `link_admin.py`; `register_link_admin_routes(admin_router)` wires routes back; `csv`, `io`, `re`, `random`, `string`, `or_`, `StreamingResponse`, `Query` imports removed from `main.py`; `main.py` reduced to 492 lines; refactor-only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; readiness wait: attempt 1 → `000`, attempt 2 → `200`; browser/live admin tests passed ✓
- Page Engine v1 Phase 4H — NFC Legacy Route Extraction (`77b6f2a`, deployed 2026-06-28) — 8 schemas, X-API-Key auth (`require_api_key`), constants (`BOOT_TIME`, `_DF_CMD`, `SAFE_COMMANDS`), and 7 route handlers moved from `main.py` into new `nfc_legacy.py`; `register_nfc_routes(app)` and `register_nfc_admin_routes(admin_router)` wire routes back; `time`, `platform`, `subprocess`, `psutil`, `Security`, `APIKeyHeader`, `BaseModel`, `IntegrityError` imports removed from `main.py`; `main.py` reduced to 302 lines; refactor-only, no behavior change, no schema change, no route change, no admin UI change, no DB migration; browser/live tests passed ✓
- Telegram Bot Self-Service Phase T1 — Bot Engine Foundation (`28559a3`, deployed 2026-06-29) — new `bot_admin.py` module; `BotClient` + `BotClientSlug` ORM models; 6 admin-only CRUD routes for managing bot clients and slug assignments; all routes under existing Basic Auth via `admin_router`; no Telegram webhook/API/token; no admin UI; no `_run_migrations()` change; DB tables auto-created by `create_all` on startup; DB backup `shadz.db.backup-before-bot-phase-t1-20260629-211249`; production verified: `/health` 200, `/admin` 401 unauth, DB tables confirmed ✓
- Phase T1A — Repo Structure Flattening (`ffb526e` + merge `3596ecb`, deployed 2026-06-30) — all 28 tracked files moved from `Desktop/shadz-os/` prefix to repo root via `git mv` (all R100); local `Desktop/` wrapper removed; VPS: `shadz.db` + `.env` moved to `/opt/shadz-os/`, `shadz.service` WorkingDirectory updated to `/opt/shadz-os`, Nginx static alias updated to `/opt/shadz-os/static/`, old `/opt/shadz-os/Desktop/shadz-os` wrapper removed; backups at `/opt/shadz-os-backups/phase-t1a-wrapper-cleanup-20260629-222954`; production verified: `/health` 200, `/admin` 401, `/` 200, static files 200, DB intact (redirect_links=35, pages=6) ✓
- Telegram Bot Self-Service Phase T1B — Webhook Runtime (`6a0439c`, deployed 2026-07-02) — new `bot_runtime.py`; public `POST /bot/telegram/webhook` protected by mandatory `TELEGRAM_WEBHOOK_SECRET` shared-secret header (fails closed if unset); `url` slug customer self-service (access code → slug menu → view/replace `destination_url` → confirm) fully live-tested end to end; `media` slug replacement explicitly NOT implemented (menu/state only, deferred to Phase T1C); in-memory session + update-id dedup state; `httpx==0.27.2` added; `TELEGRAM_BOT_TOKEN`/`TELEGRAM_WEBHOOK_SECRET` added to `.env.example` (no real values in repo); production Nginx got a new `/bot/telegram/webhook` location block (config backed up first, `nginx -t` passed, reload verified, header/secret checks confirmed 401/401/200); Telegram `setWebhook`/`getWebhookInfo` confirmed live with no errors; no DB schema change; no admin UI change; DB backup taken before creating live test data (test bot client + test slug `t1b-test-ioayej` pointed at `https://shadz.io/health`, scan_count increment confirmed) — test data cleanup deferred to T1C if desired
- Telegram Bot Self-Service Phase T1C — Media Slug Replacement (`d126dbc`, deployed 2026-07-02) — `bot_runtime.py` only (no other file changed); adds Telegram media slug replacement: customer sends a photo/document/video/GIF for an assigned `media` slug → validated against the existing `ALLOWED_MEDIA_TYPES` mime allowlist (imported directly from `media_admin.py`, not duplicated) → downloaded from Telegram via `getFile` → uploaded server-side to R2 → new `MediaAsset` row created → previous active `SlugMedia` deactivated → new active `SlugMedia` row created; `url` slug replacement behavior from T1B unchanged; no schema migration; no new env vars; no Admin UI (bot clients still managed via raw `/admin/bot/*` API calls only); local compile/import/route checks passed before commit; VPS pulled `d126dbc` by fast-forward, `shadz.service` restarted, readiness wait passed on attempt 3, local `/health` 200, public `/health` 200, `/admin` unauth 401, `GET /bot/telegram/webhook` 405 (expected — POST-only route) ✓; live Telegram test: temporary BotClient "T1C Live Test" created via `/admin/bot/clients`, active media slug `media-s9g945` assigned, Telegram login linked, media replacement flow passed live end to end; cleanup after test: slug assignment removed, temporary BotClient deactivated (no hard-delete route exists — `is_active=false` via `PATCH` is the correct/only cleanup path); no manual DB edits; **known VPS-only untracked file:** `shadz.db.backup-before-t1b-live-test-20260701-204318` remains present on the VPS filesystem from live-test prep and must not be committed to the repo (it is a local DB backup artifact, not a tracked project file)
- Telegram Bot Self-Service Phase T1D — Basic Bot Admin UI (`67fad4e`, deployed 2026-07-04) — `static/admin.html` only (no other file changed); adds a Telegram Bot Clients module to the admin panel — create bot client (returns/displays `access_code`), assign slug to bot client, client list with active/inactive status and assigned slugs (per-slug Unassign), Refresh button; reuses existing Phase T1 routes (`POST /admin/bot/clients`, `GET /admin/bot/clients`, `POST /admin/bot/clients/{id}/slugs`, `DELETE /admin/bot/clients/{id}/slugs/{slug}`); no backend changes, no webhook/runtime changes, no DB schema changes, no Page/Link/Media Engine changes; local compile + curl-based route verification passed before commit; pushed `a4a26c0..67fad4e`, VPS pulled and restarted, readiness wait passed, local/public `/health` 200, local/public `/admin` unauth 401, deployed HTML confirmed to contain Bot UI markers ✓; browser/live test: Create Bot Client, Assign Slug, assigned slug visible on refresh, Unassign all confirmed by owner ✓
- Telegram Bot Self-Service Phase T1E — Bot Admin UI Polish (`e74665b` + `23d9934`, deployed 2026-07-04) — `static/admin.html` only (no other file changed); frontend-only cleanup pass on top of T1D, no new routes, no schema/backend/bot-runtime changes:
  - `e74665b` — `goHome()` now resets the Bot Client create result box (`bc-result`), matching the existing reset pattern already used for `createResult`/`mu-result`, so stale client ID/access code no longer lingers on section re-entry; `createBotClient()` auto-fills the Assign Slug `Bot Client ID` field with the newly created client's ID, removing a manual re-typing step between Create and Assign
  - `23d9934` — `buildBotClientCard()` adds a `Telegram` status row using the existing `telegram_username`/`telegram_user_id` fields already returned by `GET /admin/bot/clients` (shows `@username`, `Linked`, or muted `Not linked yet`); `assignBotSlug()` now detects FastAPI's array-shaped validation-error `detail` (e.g. a non-integer Bot Client ID) and shows `"Invalid Bot Client ID. Please enter a whole number."` instead of a raw `[object Object]`
  - Explicitly NOT included in T1E: campaign/shared-content architecture, bulk keychain management, delete/deactivate bot client UI, Check Slug card integration, any bot runtime redesign — all remain deferred (see Not yet implemented, below)
  - No backend, DB, bot runtime, route, Nginx, or R2 changes in either commit
  - Pushed `deadfb6..23d9934`; VPS pulled `23d9934` and restarted; local `/health` 200, public `/health` 200, public `/admin` unauth 401, `shadz.service` active ✓; browser/live test confirmed: Telegram linked status / "Not linked yet" displays correctly on client cards, Create Bot Client auto-fills Assign Slug Bot Client ID, an invalid decimal Bot Client ID shows the readable error message instead of `[object Object]` ✓
- Telegram Bot Self-Service Phase T1F — Link Safety Guard (`a7510e1`, deployed 2026-07-04) — completed and closed. Added bot-only URL destination safety guard in `bot_runtime.py` for the Telegram `url` slug replacement flow: blocks SHADZ/internal/local destinations before confirmation/save, while normal external URLs still proceed to confirmation. Scope unchanged: media replacement, admin UI/routes, DB schema, Nginx, and auth untouched. Production verified (`/health` local/public 200, public `/admin` unauth 401, service active) and Telegram live-tested successfully.
- Telegram Bot Self-Service Phase T1G — Bot Client Deactivate/Delete Control (`df4d384`, deployed 2026-07-05) — completed and closed. `bot_admin.py`: new `DELETE /admin/bot/clients/{client_id}` route deletes only the `BotClient` row and its `BotClientSlug` assignment rows — `RedirectLink` slugs, media assets, and scan/history data are never touched. `bot_runtime.py`: `_handle_message` now re-checks `BotClient.is_active` on every authenticated state transition (not just the `awaiting_code` login step), so a client deactivated mid-Telegram-session is blocked immediately instead of at next login; existing login-time check reused consistently (`models.BotClient.is_active.is_(True)`). `static/admin.html`: each Bot Client card gets a confirm-gated Deactivate/Activate toggle and Delete button, wired to the existing `PATCH` route and the new `DELETE` route. Existing slug assignments are preserved when a client is deactivated and restored on reactivation. No DB migration (`is_active` already existed on `bot_clients` since Phase T1). Local verification passed (`py_compile`, `import main`, full curl-driven create/assign/deactivate/reactivate/delete lifecycle, direct mid-session deactivation simulation) before commit. Pushed `59869e1..df4d384`; VPS pulled and restarted, readiness wait passed, local/public `/health` 200, local/public `/admin` unauth 401 ✓; Admin UI and Telegram live tests passed: inactive Bot Client blocked from login/management, reactivated client works again, delete verified on a test client with the assigned slug itself confirmed untouched. Restore/cleanup polish for Bot Client lifecycle deferred to Phase T1H.
- Telegram Bot Self-Service Phase T1H — Lifecycle Audit / Closure (docs-only, 2026-07-06, docs commit: 47d3328) — completed and closed as a no-op runtime closure. Inspection confirmed the required T1H lifecycle polish was already present after T1G (deactivate, reactivate, delete, active/inactive Admin UI state, assignment preservation, inactive-client blocking in `bot_runtime.py`, inactive-client assign-slug guard). No runtime, backend, UI, or DB changes made or required. Verified read-only (`py_compile` on `bot_admin.py`/`bot_runtime.py`/`models.py`/`main.py`, plus code inspection confirming all `is_active` gates). Bulk Bot Client management and deleted-client audit trail remain out of scope / future backlog.
- Telegram Bot Self-Service Phase T1I — Check Slug → Bot Client Assign Shortcut (`57b2229`, deployed 2026-07-06) — completed and closed. `static/admin.html` only. Each Check Slug result card gets an "Assign to Bot Client" control (Bot Client ID input + Assign button + per-card message), reusing the existing `POST /admin/bot/clients/{client_id}/slugs` route as-is — no backend change. Supports active `url` and `media` slugs per existing backend rules; backend continues to reject archived slugs, `page`-type slugs, inactive bot clients, already-assigned slugs, and unknown slugs, each surfaced as a readable per-card error. Frontend adds Bot Client ID validation (required, integer-only, readable error). Existing Check Slug card controls (Edit Info, Archive/Restore, Convert row, Active Media panel, Destination row visibility rules) confirmed unaffected. No DB/schema, bot runtime, public route, Page Engine, Media Engine, Link Engine, NFC legacy, analytics, or shared-content/campaign changes. Production verified (`/health` local/public 200, public `/admin` unauth 401) and manual production browser/live tests passed for all validation and assignment cases.
- Telegram Bot Self-Service Phase T1J — Regenerate Access Code UI (`9b13c23`, deployed 2026-07-08) — completed and closed. `static/admin.html` only. Each Bot Client card gets a confirmation-gated "Regenerate Access Code" button, reusing the existing `POST /admin/bot/clients/{client_id}/regenerate-code` route (added Phase T1, `28559a3`) as-is — no backend change. On confirm, shows the newly generated access code in the Admin UI and refreshes all Bot Client cards so the displayed Access Code field updates immediately; the old access code stops working immediately after regeneration (route overwrites it, no recovery). Assigned slugs and Telegram-linked status confirmed unaffected. No DB/schema, bot runtime, public route, Page Engine, Media Engine, Link Engine, NFC legacy, redirect, scan tracking, R2, Nginx, or systemd changes. Local `py_compile` on `main.py`/`bot_admin.py`/`bot_runtime.py` passed pre-commit. Pushed `33a8df7..9b13c23`; VPS pulled and restarted; local readiness loop against `http://127.0.0.1:8000/health` passed before public checks; public `/health` 200, public `/admin` unauth 401. Manual production browser/live tests passed: button visible on every card, Cancel leaves code unchanged, Confirm shows new code, Admin page refresh persists new code, assigned slugs unchanged, Telegram linked status unchanged.
- Telegram Bot Self-Service Phase T1K — Bot Test Data Cleanup (`6523079`, deployed 2026-07-08) — completed and closed. `bot_admin.py` + `static/admin.html`. Adds an admin-only bulk cleanup workflow for removing test Bot Clients without manual DB edits: new `POST /admin/bot/clients/bulk-delete` route accepts a list of `client_ids`, de-duplicates them, and for each deletes only that client's `BotClientSlug` assignment rows and the `BotClient` row itself — unknown ids are skipped, not errored; the delete loop and commit are wrapped in `try/except: db.rollback(); raise` for transaction safety. Explicitly does not delete or modify `redirect_links`, `slug_media`, `media_assets`, `scan_logs`, actual slug records, public redirect behavior, or Telegram runtime replacement behavior — cleanup only unassigns slugs from the deleted client, mirroring the existing single-client `DELETE /admin/bot/clients/{id}` route from Phase T1G. Admin UI adds a "Select for Cleanup" checkbox per Bot Client card, Select All / Clear Selection controls, and a confirmation-gated "Delete Selected (Cleanup)" bulk bar (confirm text lists the selected IDs and warns that a real customer's bot access/assignments will be removed if selected, while slugs/media/scan data stay untouched either way) — mirrors the existing Check Slug bulk-archive/restore selection pattern. No DB/schema change, no migration, no Page Engine/Media Engine/Link Engine changes, no Nginx/Cloudflare/systemd/R2 changes. Local `py_compile` on `bot_admin.py` passed pre-commit; local curl-driven testing confirmed mixed valid/duplicate/unknown ids return correct `{deleted, skipped, errors, results}`, a real client's assigned slug survived cleanup of an unrelated test client untouched (destination, scan_count, public redirect all intact) and was successfully reassignable afterward with no orphan-row block. Pushed to `origin master`; VPS pulled `6523079` and restarted; local `/health` 200, public `/health` 200, public `/admin` unauth 401; manual production browser/live tests passed.
- Telegram Bot Self-Service Phase T1L — Final Audit / Closure (docs-only, 2026-07-08) — completed and closed. Final audit confirmed Telegram Bot v1 routes, admin controls, bot client lifecycle, slug assignment, URL/media replacement guards, and T1K cleanup controls remain intact: route wiring (`admin_router` Basic Auth on all `/admin/bot/*` routes, webhook shared-secret protection, webhook registered before `/{slug}` catch-all), bot client lifecycle (create/list/regenerate/deactivate-reactivate/delete/bulk-delete), slug assignment safety (`url`/`media` only, archived and `page` slugs rejected, one-slug-per-client), URL replacement safety (`_is_blocked_destination_url` still blocks SHADZ/internal/local destinations, allows normal external URLs), media replacement safety (still gated by `ALLOWED_MEDIA_TYPES` from `media_admin.py`, 20 MB cap, touches only the assigned media slug), and Admin UI (create/assign/regenerate/deactivate/delete/bulk-select all wired to their existing routes, no stale state). No runtime/backend/frontend/DB/schema/deployment changes were required. `python3 -m py_compile main.py bot_admin.py bot_runtime.py` passed. Telegram Bot Self-Service v1 is now closed under current v1 scope and ready for production use.
- Page Engine v1 — Phase 4I — Completion Audit (docs-only, 2026-07-11) — completed and closed as a no-op runtime closure. Audited Page Engine v1 structural completeness after Phase 4H: route registration order (`/{slug}` catch-all always last; `/admin/*` and NFC/bot routes never shadowed), slug-type dispatch in `redirect_slug` (`url`/`media`/`page`/legacy-fallback), page lifecycle (attach/detach, partial unique index `idx_page_slug_one_active`, archive/restore precedence over content_type dispatch), cross-engine type boundaries (`attach_page` requires `content_type == "page"`, `attach_media` requires `"media"`, `convert_link_type` rejects `page` as source or target), and Admin UI wiring (Page Create/Edit/Attach/Detach sections correctly call their Phase 3A/4B backend routes). Also confirmed no conflict with Telegram Bot Self-Service: `page` slugs are rejected from bot client assignment at the application layer (`bot_admin.py`), and the bot webhook route is registered before the `/{slug}` catch-all with no path overlap. Found no blocking route, lifecycle, or bot-conflict issue. No runtime, backend, frontend, or DB/schema changes were made or required — only this docs update (stale "Active slug type policy" section corrected; see below). Deferred items unchanged and explicitly out of scope for 4I: `GET /admin/pages/{page_id}` JSON read endpoint / Edit Page prefill, Phase 3E public page visual polish, and any future Page Engine UX improvements.
- Page Engine v1 Phase 4J — Public Page Visual Polish (`81656d2`, `33b088a`, deployed 2026-07-11) — completed and closed. Runtime file: `page_renderer.py` only. Delivers the premium mobile-first visual pass deferred since Phase 3E: shared dark/neutral SHADZ visual system with restrained gold accents, stronger typography and spacing hierarchy, hero/header presentation, card-based fact rows in place of plain tables, primary/secondary CTA buttons, long-text and long-URL wrapping, and consistent visual rhythm across the `invitation`, `brand_product`, and `child_safety` templates — no field-name changes, no `_PE_SAMPLES` changes required. Adds safe `_contact_href()` contact-link handling (`tel:`/`mailto:`/`http(s)`-only, all other schemes and unrecognized formats render as inert escaped text, never a link). `81656d2` introduced the polish and initial link handling; `33b088a` closed three regressions found in post-polish audit: (1) values already prefixed `mailto:`/`tel:` no longer get double-prefixed, (2) `tel:` links are only generated when the original value is composed solely of phone-number characters, so URL-like strings such as `wa.me/...` or `t.me/...` are never misclassified as phone numbers, and (3) Child Safety pages show the actual phone number as visible text in the fact card again, alongside (not instead of) the functional Call buttons. No DB/schema, API/route, scan-tracking, archive/restore, slug-attachment, Admin UI, Link Engine, Media Engine, Telegram Bot, Nginx, Cloudflare, R2, or systemd changes. Local verification: `ast.parse` syntax check on `page_renderer.py`, 55 automated regression checks covering all three templates with full/missing/XSS/long-text payloads, unknown-template fallback, and the full contact-link classification matrix (phone formats, email, `mailto:`/`tel:` prefixes, `http(s)`, Telegram/WhatsApp links with and without scheme, arbitrary text, `javascript:`/`data:`/`vbscript:` schemes) — 0 failures, single-escape-only confirmed, no dangerous scheme ever reached an `href`. Pushed `be54ddf..33b088a` to `origin/master` (fast-forward, no force). VPS deployed and live-tested: service active on `33b088a`, local readiness loop against `http://127.0.0.1:8000/health` passed before public checks, public `/health` 200, public `/` 200, public `/admin` unauthenticated 401; manual browser live tests passed for all three templates (mobile + desktop), RSVP/Contact/Call button behavior, visible Child Safety phone-number text, invalid-phone inert fallback, missing-optional-field rendering, and long-text wrapping; cross-engine smoke tests passed (`url` slug, `media` slug, archived 410, scan-count increment). Final production runtime state: `33b088a`. Page Engine v1 Phase 3E deferred-polish item is now closed by this phase (see "Not yet implemented" correction below).
- Page Engine v1 Phase 4K — Admin Page UX Polish (`2e54262`, `825bab6`, `6a18965`, deployed 2026-07-14) — completed and production live-tested. `static/admin.html` only. Delivers: Create/Edit Page stale result panels (`pc-result`/`pe-result`) now reset on section navigation; Edit Page fields clear only after a successful update, failed/error requests preserve entered values; `page`-type Check Slug cards get a "Manage Page Attachment" shortcut that opens the Attach/Detach section and prefills both the Attach and Detach slug fields, explicitly clearing Page ID and any stale attach/detach messages, with no auto-submit and no automatic attach/detach call; Attach/Detach form fields (`pa-slug`, `pa-pageId`, `pd-slug`, `pa-msg`, `pd-msg`) now reset when the admin leaves the section via existing home/navigation. URL/media slug cards, Telegram Bot flows, all backend routes/API contracts, DB/schema, authentication, and public Page Engine rendering are unchanged. Production/live-test results: tests 1–5 and 7–12 passed; test 6 found a UX/navigation issue — `pageAttachSection` opens at the bottom of the existing Check Slug results page, and on desktop the panel width/layout changes unexpectedly when opened this way (mobile does not show the width issue, but the section still opens at the bottom rather than scrolling into view). This navigation/layout issue is **not fixed** in Phase 4K and is explicitly deferred to a follow-up phase, **Phase 4Ka — Check Slug Page Optimisation**. Phase 4K is closed because all implemented functions work correctly as built; only the navigation/layout placement of the shortcut's destination section remains open, tracked separately as 4Ka.
- Page Engine v1 Phase 4Ka — Check Slug Page Optimisation (`38e476f`, deployed 2026-07-14) — completed and production live-tested. Frontend-only, `static/admin.html` only. Resolves the Phase 4K test 6 deferral: the "Manage Page Attachment" shortcut on `page`-type Check Slug cards no longer navigates to the standalone `pageAttachSection`. Instead it toggles a card-scoped inline Attach/Detach panel (`pageAttachInline-${index}`, `pai-pageId-${index}`, `pai-attach-btn/msg-${index}`, `pai-detach-btn/msg-${index}`) placed as the last child of the selected card's `.stats-box`, below its existing information/action rows and spanning the card's own width — no desktop panel-width shift, since `show()`/`GRID_SECTIONS`/`.panel.wide` are never touched by this flow. New scoped handlers `togglePageAttachInline(slug, index)`, `attachPageInline(slug, index)`, `detachPageInline(slug, index)` call the same unchanged `POST /admin/pages/attach` / `POST /admin/pages/detach` endpoints with identical payloads to the standalone `attachPage()`/`detachPage()`. Only one inline panel is open at a time — opening a different card's panel force-closes any other open panel; Page ID and both message elements are cleared every time a panel transitions from closed to open, so reopening a previously-closed panel (on the same or a different card) never shows stale state. Removed the now-dead `manageSlugPageAttachment(slug)` function (its only call site was replaced). Preserved unchanged: the standalone home-menu Attach/Detach Page workflow (`pageAttachSection`, `attachPage()`, `detachPage()`, fixed `pa-*`/`pd-*` ids), `show()`, `goHome()`, `GRID_SECTIONS`, all backend routes/API contracts, database/schema/models, authentication, Telegram Bot flows, and public Page Engine rendering. Verification: local implementation audit passed (markup placement, escaping via `escVal()` — safe because slugs are constrained server-side to `^(url|media|page)-[a-z0-9]{6}$` in `link_admin.py`, so no quote-breakout is possible — payload/endpoint parity, message/state scoping); local browser verification passed (inline placement/width, toggle/close, cross-card isolation, mobile layout, URL/media cards unaffected, home-menu workflow unaffected, neighboring grid-row stretching visually acceptable); pushed `fa0966b..38e476f` to `origin/master` (fast-forward, no force); VPS deployed and live-tested — service active on `38e476f`, local readiness loop against `http://127.0.0.1:8000/health` passed before public checks, public `/health` 200, public `/` 200, public `/admin` unauthenticated 401; production browser live tests passed for all Phase 4Ka behaviors. Final production runtime state: `38e476f`.
- Page Engine v1 Phase 4L — Template Structure Stabilization (test commit `1572fec`, 2026-07-14) — completed and closed. No runtime source file changed — no route, model, schema, database, admin, bot, public HTML, or deployment behaviour changed; `shadz.service` was not restarted. Delivered a read-only architecture audit of the Page Engine template/rendering flow, followed by a committed automated renderer behaviour lock: new `tests/test_page_renderer.py` (14 stdlib-`unittest` tests, no DB/FastAPI/`main.py` involved) covering `invitation`, `brand_product`, and `child_safety` template full-field and optional-field behaviour, malformed-JSON fallback, non-dictionary-JSON fallback, unknown-`template_type` fallback, and HTML escaping of titles/content. A structural stability decision gate then inspected `page_renderer.py` and concluded its existing internal helpers (`_raw`, `_e`, `_fact_rows`, `_contact_button`, `_contact_href`) already provide adequate, consistent normalization and escaping boundaries across all three templates — final decision **NO_RUNTIME_CHANGE**; no verified structural problem was found that justified a refactor under simplicity/surgical-change rules, so Phase 4L closes with test coverage only, not a code change. Verification: local 14/14 tests passed, `py_compile` clean, `git diff --check` clean; local `master` and `origin/master` synced at `1572fec` (fast-forward merge, no force); VPS `/opt/shadz-os` manually fast-forwarded to `1572fec` with matching 14/14 test pass, compile check, diff check, and `HEAD`/`origin/master`/`origin/HEAD` alignment; existing untracked VPS backup `shadz.db.backup-before-t1b-live-test-20260701-204318` confirmed untouched. Page Engine v1 remains open — Phase 4M and Phase 4N are not yet started.
- Page Engine v1 Phase 4M — Data Model / Compatibility Audit (`e4c0551`, deployed 2026-07-14) — completed and closed. Read-only data-model/compatibility audit of `url`/`media`/`page` slug types across public runtime, admin controls, Telegram Bot self-service, media attachment, Page Engine, archive/restore, and scan tracking. Confirmed one real defect: `bot_runtime.py`'s `awaiting_confirmation` (Telegram URL replacement) state reloaded the live `RedirectLink` and checked existence/archive status before writing `destination_url`, but never re-checked live `content_type` — a mid-session admin conversion of a slug from `url` to `media` could let a pending Telegram confirmation silently write `destination_url` onto a now-`media`-typed slug. Fix: one-line guard extension in `bot_runtime.py` — `if not link or link.is_archived is True or link.content_type != "url":` — rejects the write and resets to the slug menu using the same existing "slug no longer available" pattern already used for missing/archived slugs; no session-flow redesign, session-cached data remains display/navigation-only. New `tests/test_bot_runtime.py` (4 stdlib-`unittest` tests, isolated in-memory SQLite, no network calls) covers: URL confirmation succeeds when live type is still `url`; URL confirmation rejected with `destination_url` unchanged when the slug was converted to `media` before confirmation; existing media-upload `content_type != "media"` guard still rejects correctly (unrelated media-replacement behaviour confirmed unchanged); media-upload state still re-prompts correctly on unsupported message types. No model, schema, migration, or database write; no admin UI, Nginx, or systemd change; media replacement, admin conversion behaviour, and all other bot states untouched; slug type policy unchanged (`url`/`media`/`page` remain the only official types). `idx_slug_media_one_active` (a `SlugMedia` partial unique index matching the existing `PageSlugAttachment` pattern) was identified as optional future hardening only and explicitly deferred, not applied — no mandatory data migration was required. Verification: local 18/18 tests passed (4 new + 14 existing), `py_compile` clean, `git diff --check` clean; local `master` and `origin/master` synced at `e4c0551` (fast-forward push, no force); VPS `/opt/shadz-os` fast-forwarded to `e4c0551`, local readiness against `http://127.0.0.1:8000/health` reached 200 before public checks, `shadz.service` active; public `/health` 200, public `/` 200, public `/admin` unauthenticated 401; Telegram Bot live test passed — URL slug replacement flow and post-update redirect behaviour both confirmed correct; production DB read-only audit returned zero findings for duplicate active `SlugMedia`, orphan `SlugMedia`, orphan `BotClientSlug` by client, orphan `BotClientSlug` by slug, and bot assignments using unsupported slug types. Page Engine v1 remains open — Phase 4N (Production Polish / v1 Closure) is not yet started.
- Page Engine v1 Phase 4N — Production Polish / v1 Closure (`2f7cf8d`, `5862b36`, deployed 2026-07-15) — completed and closed. **Page Engine v1 is now complete and closed.** Read-only audit found `page_admin.py` had zero automated test coverage; added `tests/test_page_admin.py` (17 stdlib-`unittest` tests, isolated in-memory SQLite, no `main.py`/real `shadz.db` involved) covering create/update validation, attach content-type/existence checks, re-attach history preservation, and detach behaviour — no Page Engine runtime change. Audited whether `Page.status` should gate public rendering; decision was to leave it unchanged — attach/detach remains the sole publish mechanism (unchanged since Phase 3A), `status` stays informational only. VPS verification then surfaced a Phase 4N incident: `tests/test_bot_runtime.py` assumed `TELEGRAM_BOT_TOKEN` would be unset; on the VPS, where the token is configured, this made the suite place real outbound requests to the Telegram Bot API with synthetic test `chat_id` values, and the resulting `httpx.HTTPStatusError` was logged via its default string form, which embeds the full request URL — exposing the bot token in application logs, since Telegram's Bot API puts the token in the URL path rather than a header (no token value recorded in this document). Fix in `bot_runtime.py` only: `_send_message` and `_download_telegram_file` no longer log or raise the raw exception on `httpx.HTTPStatusError` — `_send_message` logs only `chat_id`, HTTP status, and exception class; `_download_telegram_file` raises a sanitized `RuntimeError` with a safe operation label and status code, chained with `from None` so the original token-bearing exception can never surface via a caller's `logger.exception(...)`; non-HTTP exceptions are logged by class name only; no change to outbound payloads or the existing fail-safe token guard. `tests/test_bot_runtime.py` updated: the 4 existing state-machine tests now patch `bot_runtime._send_message` with `AsyncMock`, removing the environment-dependent assumption; added 4 new tests mocking `httpx.AsyncClient` to simulate Telegram HTTP failures and assert the token/API URL never appear in logs or exception messages, with no exception chaining. Incident resolved on the VPS: the exposed bot token was rotated, `.env` updated, and the Telegram webhook re-registered against the new token. No database/schema change, no migration, no Page Engine runtime change, no admin UI/route/Nginx/systemd/Cloudflare change, no dependency added. Verification: local 39/39 tests passed, `py_compile` clean, `git diff --check` clean; fake-token/socket-blocked proof run confirmed no test in `tests/test_bot_runtime.py` can reach the network regardless of token state; local `master`/`origin/master` fast-forwarded to `2f7cf8d` then `5862b36` (two fast-forward pushes, no force); VPS `/opt/shadz-os` synced to `5862b36`, `HEAD`/`origin/master` matched, 39/39 tests passed on VPS, `shadz.service` restarted, local readiness against `http://127.0.0.1:8000/health` reached 200 before public checks; public `/health` 200, public `/` 200, public `/admin` unauthenticated 401; Telegram webhook restored and live-tested after token rotation — `/start`, access-code login, URL slug lookup/update, and media slug replacement all confirmed working. Final production runtime state: `5862b36`. No remaining Phase 4N runtime work.

### Active slug type policy

- Current official slug types: `url`, `media`, `page` — all three are live and active, not planned/future
- `url` — behavior controlled by `destination_url`; admin shows Destination row with View Full / Open ↗
- `media` — behavior controlled by active `SlugMedia` / `MediaAsset` attachment; admin hides Destination row entirely
- `page` — Page Engine is live (since Phase 3A–3D, public rendering since Phase 3C); `page` slugs render through Page Engine via their active `PageSlugAttachment` → `Page` row (`page_public.py` / `page_renderer.py`), not through `destination_url`. Admin still shows the Destination row for `page` slugs per Patch 5.2 (harmless — displays "Not set" since page slugs carry no `destination_url`); this is cosmetic only and does not affect rendering. `page` slugs are explicitly excluded from Telegram Bot Self-Service assignment (`bot_admin.py` rejects `content_type == "page"` at the application layer) — only `url` and `media` slugs may be assigned to a bot client.
- **`slug` = permanent NFC identity; `content_type` = current behavior; `destination_url` = preserved even when slug converts to media**
- Confirmed structurally complete and conflict-free with Telegram Bot Self-Service as of Phase 4I (2026-07-11) — see Completed milestones
- Public page visual polish (deferred as "Phase 3E" through Phase 4I) shipped and closed as Phase 4J (`81656d2`, `33b088a`, deployed 2026-07-11) — see Completed milestones

### Type Conversion rules (v0.1)

- `url → media`: allowed; `destination_url` preserved; no media auto-attached; public shows media-not-ready until media attached
- `media → url`: requires `destination_url`; blocked if active `SlugMedia` exists (must detach first); public redirects on success
- `page` conversion: rejected in v0.1
- `null` / legacy `content_type`: conversion rejected
- Media attach endpoint guard unchanged: only `content_type == "media"` slugs can attach media
- Public redirect route: branches on `content_type`, not slug prefix — slug string never changes

### Source file layout (as of Phase T1)

- `main.py` — FastAPI app assembly layer; public routes, auth, migrations; imports and wires `link_admin`, `media_admin`, `page_admin`, `page_public`, `link_public`, `nfc_legacy`, `bot_admin`; catch-all `/{slug}` route stays here for route-order safety
- `bot_admin.py` — Bot Engine admin schemas, access code generator, and route registration (`register_bot_admin_routes()`); all 6 `/admin/bot/*` routes; no Telegram API calls; no webhook; no public coupling
- `bot_runtime.py` — Telegram webhook route (`register_bot_webhook_routes(app)`), in-memory chat session/dedup state, `httpx`-based `_send_message`; customer-facing `url` slug self-service only; media slug replacement deferred to Phase T1C; no admin coupling
- `nfc_legacy.py` — NFC legacy system and internal utility routes; X-API-Key auth (`require_api_key`); `register_nfc_routes(app)` (6 routes: `/status`, `/run-command`, `/nfc/*`, `/r/{tag_id}`) and `register_nfc_admin_routes(admin_router)` (`PATCH /admin/nfc`); all NFC schemas including `NFCStats`; `BOOT_TIME`, `SAFE_COMMANDS`; no Page Engine coupling
- `link_admin.py` — Link Engine admin schemas, slug helpers, and route registration (`register_link_admin_routes()`); all 10 `/admin/link*` and `/admin/links/*` routes; slug naming constants (`VALID_CONTENT_TYPES`, `SLUG_PATTERN`) and helpers (`is_valid_slug`, `generate_slug`); no public coupling
- `media_admin.py` — Media Engine admin schemas, R2 helpers, and route registration (`register_media_admin_routes()`); all 8 `/admin/media/*` routes; no public coupling
- `link_public.py` — public link/media HTML generators and handlers (`expired_page_response`, `serve_public_media`); no admin coupling
- `page_renderer.py` — Page Engine public renderer only (`_render_page_html()`); imported by `page_public.py`
- `page_admin.py` — Page Engine admin schemas, helpers, and route registration (`register_page_admin_routes()`); uses `get_active_page_attachment` from `page_queries`
- `page_public.py` — public page handler (`serve_public_page(slug, db)`); imports from `page_queries` and `page_renderer` only — no admin coupling
- `page_queries.py` — shared DB query helpers (`get_active_page_attachment`); no FastAPI or admin dependencies
- `models.py` — SQLAlchemy ORM models and constants
- `database.py` — SQLAlchemy engine and session factory

### Not yet implemented

- Phase 3E — Public page visual upgrade — no longer deferred; shipped as Page Engine v1 Phase 4J (`81656d2`, `33b088a`, deployed 2026-07-11) — see Completed milestones
- Type Conversion v0.2 — page conversion, extended conversion rules (not started)
- Analytics / Scan Tracking Chart — not started
- `GET /admin/pages/{page_id}` JSON read endpoint — to support Edit Page pre-fill in admin UI; not required for current v1 — confirmed still deferred, not part of Phase 4I, 4K, or 4Ka
- Phase 4Ka — Check Slug Page Optimisation — no longer deferred; shipped and closed (`38e476f`, deployed 2026-07-14) — see Completed milestones
- Phase 4L — Template Structure Stabilization — no longer not-started; shipped and closed (test commit `1572fec`, 2026-07-14) as a docs+test-only closure (audit + decision gate concluded **NO_RUNTIME_CHANGE**; no runtime file changed) — see Completed milestones
- Phase 4M — Data Model / Compatibility Audit — no longer not-started; shipped and closed (`e4c0551`, deployed 2026-07-14) as a read-only audit plus a one-line Telegram Bot URL-confirmation guard fix and 4 new regression tests — no schema/migration change; `idx_slug_media_one_active` deferred as optional future hardening — see Completed milestones
- Phase 4N — Production Polish / v1 Closure — no longer not-started; shipped and closed (`2f7cf8d`, `5862b36`, deployed 2026-07-15) as Page Engine admin regression test coverage plus a Telegram bot secret-safe logging fix — see Completed milestones. **Page Engine v1 is now complete and closed.**
- Future Page Engine UX improvements generally (beyond 3E polish, 4K polish, 4Ka polish, 4L stabilization, and the read-endpoint gap) — not scoped or started
- Proper UI login/logout system — deferred; Basic Auth popup is accepted for now
- Role-based admin security — deferred until multi-admin use case arises
- **Bot Engine — remaining work:**
  - Optional cleanup of Phase T1B live test data (test bot client + slug `t1b-test-ioayej`) — still outstanding; not touched during T1C, T1D, or T1G (T1C's own temporary test client/assignment were cleaned up, see T1C changelog entry, but this is separate T1B-era test data)
  - **Phase T1K — closed (`6523079`, deployed 2026-07-08):** Bot test data cleanup controls added — `POST /admin/bot/clients/bulk-delete` (`bot_admin.py`) + Bot Client card cleanup selection UI (`static/admin.html`). Removes only `BotClient` rows and their `BotClientSlug` assignment rows for the selected ids; slugs, media, and scan data untouched. Deleted-client history/audit trail remains future backlog / out of scope, not yet scheduled.
  - **Phase T1J — closed (`9b13c23`, deployed 2026-07-08):** Regenerate Access Code UI added to `static/admin.html`; no backend change (reuses `POST /admin/bot/clients/{id}/regenerate-code` from Phase T1). Deactivate/reactivate/delete were exposed in Phase T1G (`df4d384`).
  - **Phase T1H — closed as lifecycle audit (docs-only, 2026-07-06):** confirmed the required T1H lifecycle polish was already present after T1G; no runtime changes made.
  - **Phase T1I — closed (`57b2229`, deployed 2026-07-06):** Check Slug → Bot Client assign shortcut added to `static/admin.html`; no backend change.
  - Deleted-client history/audit trail remains future backlog / out of scope, not yet scheduled (bulk cleanup itself resolved by T1K).
  - Client portal; role-based access
  - Future cleanup debt: `bot_runtime.py` reuses R2/storage helpers imported directly from `media_admin.py` (`ALLOWED_MEDIA_TYPES`, `_get_r2_client`, `_make_storage_key`, `_make_public_url`); if a third module needs them, extract into a shared media storage module — not done in T1C to keep the change surgical

**Naming note (resolved):** an earlier version of this roadmap labeled the Telegram webhook runtime "Phase T2" and reserved "Phase T1B" for the admin UI, then a later revision retitled the still-unbuilt admin UI work as "Phase T1C". The work session that actually shipped and deployed commit `d126dbc` used "Phase T1C" for the Telegram **media slug replacement flow** instead — confirmed by the runtime commit message and owner sign-off. This doc now follows that usage: T1B = webhook runtime + url self-service, T1C = media slug replacement via Telegram, T1D = basic Bot Admin UI (`67fad4e`, deployed 2026-07-04).

### Local Git / repo structure (Phase T1A — completed 2026-06-30)

**Canonical local repo root:** `~/Desktop/shadz-os`
**Canonical VPS app/repo root:** `/opt/shadz-os`

Phase T1A resolved the file-nesting problem. All 28 tracked files/dirs were moved from `Desktop/shadz-os/` to repo root using `git mv` (all R100 renames — history preserved). Deployed and production-verified.

Do NOT use: `~/Desktop/shadz-os/Desktop/shadz-os` or `/opt/shadz-os/Desktop/shadz-os` — old nested paths, eliminated.

**Local workflow:**
- Repo root: `~/Desktop/shadz-os`
- Stage files explicitly by name — never `git add .` or `git add -A`
- Verify: `pwd`, `git status --short`, `ls CLAUDE.md`

**VPS workflow:**
- App root: `cd /opt/shadz-os`
- Never: `cd /opt/shadz-os/Desktop/shadz-os`
- `shadz.service` WorkingDirectory: `/opt/shadz-os`
- Nginx static alias: `/opt/shadz-os/static/`
- DB: `/opt/shadz-os/shadz.db`
- `.env`: `/opt/shadz-os/.env`
- Backups from T1A migration: `/opt/shadz-os-backups/phase-t1a-wrapper-cleanup-20260629-222954` (do not delete)

### Guardrails for future sessions

- Future work must be explicitly prompted per session
- Do not infer or start roadmap tasks from this document
- Do not implement Analytics, Page Engine, Bot Engine, login/logout, or any other future feature unless the current prompt explicitly asks for it
- Do not modify `main.py`, database schema, Nginx, or auth unless the task explicitly requires it
- Always verify `/`, `/admin` (→ 401), `/health` (→ 200) after any deploy using GET-based curl only
- Do not move `.git`, run `git reset --hard`, or restructure the local repo without an explicit approved plan
