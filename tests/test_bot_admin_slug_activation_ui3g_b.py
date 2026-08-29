"""UI3G-B: Assigned Slug Activation Visibility.

GET /admin/bot/clients must expose, per assigned slug, enough read-only
activation information for the Admin UI to distinguish exactly:
  Activated / Awaiting Telegram Login / Activation Sync Required /
  Ownership Conflict / Legacy

Guards:
  - ActivationRecord is None -> "Legacy" (never "unactivated").
  - Legacy assigned slugs stay present in the response (outer join).
  - Existing AssignedSlugOut fields remain present and unchanged.
  - The list/read path never mutates ActivationRecord state.

Isolated in-memory SQLite — never touches the real shadz.db.
"""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_admin
import models
from database import Base, get_db


class AssignedSlugActivationVisibilityTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        bot_admin.register_bot_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.close()

    # ── fixtures ──────────────────────────────────────────────────────────
    def _client(self, name, code, telegram_user_id=None):
        c = models.BotClient(
            client_name=name, access_code=code, telegram_user_id=telegram_user_id
        )
        self.db.add(c)
        self.db.commit()
        self.db.refresh(c)
        return c

    def _link(self, slug, content_type="url"):
        link = models.RedirectLink(
            slug=slug, destination_url="https://x.example.com",
            content_type=content_type, is_archived=False,
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _assign_row(self, client_id, slug):
        self.db.add(models.BotClientSlug(bot_client_id=client_id, slug=slug))
        self.db.commit()

    def _record(self, slug, status="unactivated", owner_client_id=None, activated_at=None):
        ar = models.ActivationRecord(
            slug=slug, activation_token=f"tok-{slug}",
            activation_status=status, owner_client_id=owner_client_id,
            activated_at=activated_at,
        )
        self.db.add(ar)
        self.db.commit()
        return ar

    def _slug_payload(self, client_id, slug):
        res = self.client.get("/admin/bot/clients")
        self.assertEqual(res.status_code, 200)
        client = next(c for c in res.json() if c["id"] == client_id)
        return next(s for s in client["assigned_slugs"] if s["slug"] == slug)

    # ── 1. no ActivationRecord -> Legacy ─────────────────────────────────
    def test_no_activation_record_is_legacy(self):
        c = self._client("Legacy Co", "LEG001", telegram_user_id="900")
        self._link("url-legacy")
        self._assign_row(c.id, "url-legacy")

        s = self._slug_payload(c.id, "url-legacy")
        self.assertEqual(s["activation_state"], "Legacy")
        self.assertIsNone(s["activation_status"])
        self.assertIsNone(s["activation_owner_client_id"])

    # ── 2. unactivated / unowned + unlinked client -> Awaiting Telegram Login ──
    def test_unactivated_unowned_is_awaiting_login(self):
        c = self._client("Pending Co", "PEN001", telegram_user_id=None)
        self._link("url-pending")
        self._assign_row(c.id, "url-pending")
        self._record("url-pending", status="unactivated", owner_client_id=None)

        s = self._slug_payload(c.id, "url-pending")
        self.assertEqual(s["activation_state"], "Awaiting Telegram Login")
        self.assertEqual(s["activation_status"], "unactivated")

    # ── 3. activated & owned by this client -> Activated ─────────────────
    def test_activated_owned_by_this_client(self):
        c = self._client("Live Co", "LIV001", telegram_user_id="901")
        self._link("url-live")
        self._assign_row(c.id, "url-live")
        self._record(
            "url-live", status="activated", owner_client_id=c.id,
            activated_at=datetime.now(timezone.utc),
        )

        s = self._slug_payload(c.id, "url-live")
        self.assertEqual(s["activation_state"], "Activated")
        self.assertEqual(s["activation_owner_client_id"], c.id)

    # ── 4a. owned by a different client -> Ownership Conflict ────────────
    def test_owned_by_other_client_is_conflict(self):
        c = self._client("Claim Co", "CLA001", telegram_user_id="902")
        other = self._client("Other Co", "OTH001", telegram_user_id="903")
        self._link("url-conflict")
        self._assign_row(c.id, "url-conflict")
        self._record(
            "url-conflict", status="activated", owner_client_id=other.id,
            activated_at=datetime.now(timezone.utc),
        )

        s = self._slug_payload(c.id, "url-conflict")
        self.assertEqual(s["activation_state"], "Ownership Conflict")

    # ── 4b. linked client, record neither activated-by-it nor owned elsewhere
    #        -> Activation Sync Required ────────────────────────────────────
    def test_linked_but_unreconciled_is_sync_required(self):
        c = self._client("Sync Co", "SYN001", telegram_user_id="904")
        self._link("url-sync")
        self._assign_row(c.id, "url-sync")
        self._record("url-sync", status="unactivated", owner_client_id=None)

        s = self._slug_payload(c.id, "url-sync")
        self.assertEqual(s["activation_state"], "Activation Sync Required")

    # ── 5. existing AssignedSlugOut fields remain present ────────────────
    def test_existing_fields_remain_present(self):
        c = self._client("Fields Co", "FLD001", telegram_user_id="905")
        link = self._link("url-fields")
        link.notes = "keep me"
        self.db.commit()
        self._assign_row(c.id, "url-fields")

        s = self._slug_payload(c.id, "url-fields")
        for key in ("slug", "content_type", "notes", "is_archived", "assigned_at"):
            self.assertIn(key, s)
        self.assertEqual(s["slug"], "url-fields")
        self.assertEqual(s["content_type"], "url")
        self.assertEqual(s["notes"], "keep me")
        self.assertFalse(s["is_archived"])

    # ── 6. read path must not mutate ActivationRecord state ─────────────
    def test_list_path_does_not_mutate_activation_records(self):
        c = self._client("Immutable Co", "IMM001", telegram_user_id=None)
        for slug, st, owner in (
            ("url-im1", "unactivated", None),
            ("url-im2", "activated", None),
        ):
            self._link(slug)
            self._assign_row(c.id, slug)
            self._record(slug, status=st, owner_client_id=owner)

        def snapshot():
            self.db.expire_all()
            return {
                ar.slug: (ar.activation_status, ar.owner_client_id,
                          ar.activated_at, ar.activation_token)
                for ar in self.db.query(models.ActivationRecord).all()
            }

        before = snapshot()
        self.client.get("/admin/bot/clients")
        self.client.get("/admin/bot/clients")
        self.assertEqual(before, snapshot())

    # ── 7. Legacy assigned slug is not dropped by the join ──────────────
    def test_legacy_slug_still_listed_alongside_activated(self):
        c = self._client("Mixed Co", "MIX001", telegram_user_id="906")
        for slug in ("url-mix-legacy", "url-mix-live"):
            self._link(slug)
            self._assign_row(c.id, slug)
        self._record(
            "url-mix-live", status="activated", owner_client_id=c.id,
            activated_at=datetime.now(timezone.utc),
        )

        res = self.client.get("/admin/bot/clients")
        client = next(x for x in res.json() if x["id"] == c.id)
        got = {s["slug"]: s["activation_state"] for s in client["assigned_slugs"]}
        self.assertEqual(got, {
            "url-mix-legacy": "Legacy",
            "url-mix-live": "Activated",
        })


if __name__ == "__main__":
    unittest.main()
