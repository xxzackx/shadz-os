"""UI3G-C: Bot Client card identity + Last Activity.

Read-only additions to GET /admin/bot/clients:
  - telegram_user_id / telegram_username / telegram_display_name / created_at
    are already returned; verified here for linked and unlinked clients.
  - last_activity_at / last_activity_source: newest of existing timestamps
    only (Slug activated > Slug assigned > Client updated > Client created).

Isolated in-memory SQLite — never touches the real shadz.db.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_admin
import models
from database import Base, get_db

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _naive(dt: datetime) -> datetime:
    """Drop tzinfo for comparison — SQLite returns naive timestamps and the
    JSON response echoes them back without an offset."""
    return dt.replace(tzinfo=None)


def _parsed(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=None)


class BotClientIdentityActivityTests(unittest.TestCase):
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

    # ── fixtures ─────────────────────────────────────────────────────────
    def _client(self, name, code, telegram_user_id=None, telegram_username=None,
                telegram_display_name=None, created_at=BASE, updated_at=BASE):
        c = models.BotClient(
            client_name=name, access_code=code,
            telegram_user_id=telegram_user_id, telegram_username=telegram_username,
            telegram_display_name=telegram_display_name,
            created_at=created_at, updated_at=updated_at,
        )
        self.db.add(c)
        self.db.commit()
        self.db.refresh(c)
        return c

    def _link(self, slug):
        self.db.add(models.RedirectLink(
            slug=slug, destination_url="https://x.example.com",
            content_type="url", is_archived=False,
        ))
        self.db.commit()

    def _assign(self, client_id, slug, assigned_at):
        row = models.BotClientSlug(bot_client_id=client_id, slug=slug)
        row.created_at = assigned_at
        self.db.add(row)
        self.db.commit()

    def _record(self, slug, status="unactivated", owner_client_id=None, activated_at=None):
        self.db.add(models.ActivationRecord(
            slug=slug, activation_token=f"tok-{slug}",
            activation_status=status, owner_client_id=owner_client_id,
            activated_at=activated_at,
        ))
        self.db.commit()

    def _payload(self, client_id):
        res = self.client.get("/admin/bot/clients")
        self.assertEqual(res.status_code, 200)
        return next(c for c in res.json() if c["id"] == client_id)

    # ── 1. telegram_user_id present linked / safe unlinked ───────────────
    def test_telegram_user_id_linked_and_unlinked(self):
        linked = self._client("Linked Co", "LNK001", telegram_user_id="555",
                               telegram_username="jane", telegram_display_name="Jane R")
        unlinked = self._client("Unlinked Co", "UNL001")

        pl = self._payload(linked.id)
        self.assertEqual(pl["telegram_user_id"], "555")
        self.assertEqual(pl["telegram_username"], "jane")
        self.assertEqual(pl["telegram_display_name"], "Jane R")

        pu = self._payload(unlinked.id)
        self.assertIsNone(pu["telegram_user_id"])
        self.assertIsNone(pu["telegram_username"])
        self.assertIsNone(pu["telegram_display_name"])

    # ── 2. created_at still present ─────────────────────────────────────
    def test_created_at_present(self):
        c = self._client("Created Co", "CRT001", created_at=BASE, updated_at=BASE)
        pl = self._payload(c.id)
        self.assertIn("created_at", pl)
        self.assertEqual(_parsed(pl["created_at"]), _naive(BASE))

    # ── 3/7. no activity beyond creation -> Client created fallback ─────
    def test_creation_is_fallback(self):
        c = self._client("Fresh Co", "FRS001", created_at=BASE, updated_at=BASE)
        pl = self._payload(c.id)
        self.assertEqual(pl["last_activity_source"], "Client created")
        self.assertEqual(_parsed(pl["last_activity_at"]), _naive(BASE))

    # ── 4. activation activated_at newest -> "Slug activated" ───────────
    def test_activated_at_wins_when_newest(self):
        c = self._client("Live Co", "LIV001", telegram_user_id="900",
                         created_at=BASE, updated_at=BASE + timedelta(hours=1))
        self._link("url-live")
        self._assign(c.id, "url-live", assigned_at=BASE + timedelta(hours=2))
        self._record("url-live", status="activated", owner_client_id=c.id,
                     activated_at=BASE + timedelta(hours=5))

        pl = self._payload(c.id)
        self.assertEqual(pl["last_activity_source"], "Slug activated")
        self.assertEqual(_parsed(pl["last_activity_at"]), _naive(BASE + timedelta(hours=5)))
        # slug-level activated_at is additively exposed
        s = next(x for x in pl["assigned_slugs"] if x["slug"] == "url-live")
        self.assertEqual(_parsed(s["activated_at"]), _naive(BASE + timedelta(hours=5)))

    # ── 5. slug assigned_at newest -> "Slug assigned" ──────────────────
    def test_assigned_at_wins_when_newest(self):
        c = self._client("Assign Co", "ASN001", telegram_user_id="901",
                         created_at=BASE, updated_at=BASE + timedelta(hours=1))
        self._link("url-asn")
        self._assign(c.id, "url-asn", assigned_at=BASE + timedelta(hours=9))
        self._record("url-asn", status="unactivated", owner_client_id=None,
                     activated_at=None)

        pl = self._payload(c.id)
        self.assertEqual(pl["last_activity_source"], "Slug assigned")
        self.assertEqual(_parsed(pl["last_activity_at"]), _naive(BASE + timedelta(hours=9)))

    # ── 6. client updated_at newest -> "Client updated" ────────────────
    def test_updated_at_wins_when_newest(self):
        c = self._client("Upd Co", "UPD001", telegram_user_id="902",
                         created_at=BASE, updated_at=BASE + timedelta(days=3))
        self._link("url-upd")
        self._assign(c.id, "url-upd", assigned_at=BASE + timedelta(hours=2))
        self._record("url-upd", status="activated", owner_client_id=c.id,
                     activated_at=BASE + timedelta(hours=4))

        pl = self._payload(c.id)
        self.assertEqual(pl["last_activity_source"], "Client updated")
        self.assertEqual(_parsed(pl["last_activity_at"]), _naive(BASE + timedelta(days=3)))

    # ── 8. GET must not mutate any timestamp / activation state ────────
    def test_list_path_is_non_mutating(self):
        c = self._client("Immut Co", "IMM001", telegram_user_id="903",
                         created_at=BASE, updated_at=BASE + timedelta(hours=1))
        self._link("url-im")
        self._assign(c.id, "url-im", assigned_at=BASE + timedelta(hours=2))
        self._record("url-im", status="activated", owner_client_id=c.id,
                     activated_at=BASE + timedelta(hours=3))

        def snapshot():
            self.db.expire_all()
            cl = self.db.get(models.BotClient, c.id)
            ar = self.db.query(models.ActivationRecord).filter_by(slug="url-im").first()
            bcs = self.db.query(models.BotClientSlug).filter_by(slug="url-im").first()
            return (cl.created_at, cl.updated_at, ar.activation_status,
                    ar.owner_client_id, ar.activated_at, ar.activation_token,
                    bcs.created_at)

        before = snapshot()
        self.client.get("/admin/bot/clients")
        self.client.get("/admin/bot/clients")
        self.assertEqual(before, snapshot())

    # ── 9. UI3G-B activation fields unchanged ─────────────────────────
    def test_ui3g_b_activation_fields_unchanged(self):
        c = self._client("B Co", "BBB001", telegram_user_id="904",
                         created_at=BASE, updated_at=BASE)
        self._link("url-b-legacy")
        self._assign(c.id, "url-b-legacy", assigned_at=BASE + timedelta(hours=1))
        self._link("url-b-live")
        self._assign(c.id, "url-b-live", assigned_at=BASE + timedelta(hours=1))
        self._record("url-b-live", status="activated", owner_client_id=c.id,
                     activated_at=BASE + timedelta(hours=2))

        pl = self._payload(c.id)
        by_slug = {s["slug"]: s for s in pl["assigned_slugs"]}
        self.assertEqual(by_slug["url-b-legacy"]["activation_state"], "Legacy")
        self.assertIsNone(by_slug["url-b-legacy"]["activation_status"])
        self.assertIsNone(by_slug["url-b-legacy"]["activation_owner_client_id"])
        self.assertEqual(by_slug["url-b-live"]["activation_state"], "Activated")
        self.assertEqual(by_slug["url-b-live"]["activation_status"], "activated")
        self.assertEqual(by_slug["url-b-live"]["activation_owner_client_id"], c.id)
        for key in ("slug", "content_type", "notes", "is_archived", "assigned_at"):
            self.assertIn(key, by_slug["url-b-live"])


if __name__ == "__main__":
    unittest.main()
