"""UI3G-C.1: Bot Client Control Centre timestamps must serialize with
explicit UTC semantics.

SQLite returns DateTime(timezone=True) columns as naive datetimes; every
SHADZ writer stores datetime.now(timezone.utc). Without an explicit offset
in the JSON, the browser's `new Date(...)` misreads stored UTC as local
time (Bot Client 13 showed 7h early). bot_admin now tags these fields UTC
on serialization only (matching link_admin._as_utc) — no DB mutation, no
offset math.

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

# Deliberately NAIVE — mimics how SQLite hands timestamps back to SQLAlchemy.
NAIVE = datetime(2026, 8, 27, 10, 14, 48)
NAIVE_ASSIGN = datetime(2026, 8, 27, 10, 15, 54)


def _has_utc_offset(iso: str) -> bool:
    return iso.endswith("Z") or iso.endswith("+00:00")


def _instant(iso: str) -> datetime:
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc)


class BotClientUtcSerializationTests(unittest.TestCase):
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

    def _client(self, name, code, created_at, updated_at, telegram_user_id=None):
        c = models.BotClient(
            client_name=name, access_code=code, telegram_user_id=telegram_user_id,
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

    # ── 1. naive UTC DB datetime -> API output carries explicit UTC ──────
    def test_naive_db_datetime_serialized_with_utc_offset(self):
        c = self._client("C13", "AAA111", created_at=NAIVE, updated_at=NAIVE,
                         telegram_user_id="900")
        self._link("url-13")
        self._assign(c.id, "url-13", assigned_at=NAIVE_ASSIGN)
        self._record("url-13", status="activated", owner_client_id=c.id,
                     activated_at=NAIVE_ASSIGN + timedelta(minutes=1))

        pl = self._payload(c.id)
        for field in ("created_at", "updated_at", "last_activity_at"):
            self.assertTrue(_has_utc_offset(pl[field]), f"{field}={pl[field]!r}")
        s = pl["assigned_slugs"][0]
        self.assertTrue(_has_utc_offset(s["assigned_at"]), s["assigned_at"])
        self.assertTrue(_has_utc_offset(s["activated_at"]), s["activated_at"])

        # The instant is unchanged — 10:14:48 is now unambiguously UTC,
        # not shifted by any offset.
        self.assertEqual(_instant(pl["created_at"]),
                         NAIVE.replace(tzinfo=timezone.utc))

    # ── 2. already-aware UTC datetime stays correct (no double convert) ──
    def test_aware_datetime_not_double_converted(self):
        aware = datetime(2026, 8, 27, 10, 14, 48, tzinfo=timezone.utc)
        c = self._client("CAware", "AAA222", created_at=aware, updated_at=aware)

        pl = self._payload(c.id)
        self.assertTrue(_has_utc_offset(pl["created_at"]))
        self.assertEqual(_instant(pl["created_at"]), aware)

    # ── 3. GET does not shift any stored timestamp ─────────────────────
    def test_get_does_not_mutate_db_timestamps(self):
        c = self._client("CImmut", "AAA333", created_at=NAIVE,
                         updated_at=NAIVE + timedelta(hours=1), telegram_user_id="901")
        self._link("url-im")
        self._assign(c.id, "url-im", assigned_at=NAIVE_ASSIGN)
        self._record("url-im", status="activated", owner_client_id=c.id,
                     activated_at=NAIVE_ASSIGN + timedelta(minutes=2))

        def snapshot():
            self.db.expire_all()
            cl = self.db.get(models.BotClient, c.id)
            ar = self.db.query(models.ActivationRecord).filter_by(slug="url-im").first()
            bcs = self.db.query(models.BotClientSlug).filter_by(slug="url-im").first()
            return (cl.created_at, cl.updated_at, ar.activated_at, bcs.created_at,
                    ar.activation_status, ar.owner_client_id)

        before = snapshot()
        self.client.get("/admin/bot/clients")
        self.client.get("/admin/bot/clients")
        self.assertEqual(before, snapshot())

    # ── 4. Last Activity selection + source label unchanged ────────────
    def test_last_activity_selection_unchanged(self):
        c = self._client("CSel", "AAA444", created_at=NAIVE,
                         updated_at=NAIVE + timedelta(hours=1), telegram_user_id="902")
        self._link("url-sel")
        self._assign(c.id, "url-sel", assigned_at=NAIVE + timedelta(hours=2))
        self._record("url-sel", status="activated", owner_client_id=c.id,
                     activated_at=NAIVE + timedelta(hours=5))

        pl = self._payload(c.id)
        self.assertEqual(pl["last_activity_source"], "Slug activated")
        self.assertEqual(_instant(pl["last_activity_at"]),
                         (NAIVE + timedelta(hours=5)).replace(tzinfo=timezone.utc))

        # assigned_at newest -> "Slug assigned" still selected
        c2 = self._client("CSel2", "AAA555", created_at=NAIVE,
                          updated_at=NAIVE + timedelta(hours=1), telegram_user_id="903")
        self._link("url-sel2")
        self._assign(c2.id, "url-sel2", assigned_at=NAIVE + timedelta(hours=9))
        self._record("url-sel2", status="unactivated", owner_client_id=None)
        pl2 = self._payload(c2.id)
        self.assertEqual(pl2["last_activity_source"], "Slug assigned")

    # ── 5. UI3G-B activation fields/behaviour unchanged ────────────────
    def test_ui3g_b_activation_unchanged(self):
        c = self._client("CB", "AAA666", created_at=NAIVE, updated_at=NAIVE,
                         telegram_user_id="904")
        self._link("url-b-legacy")
        self._assign(c.id, "url-b-legacy", assigned_at=NAIVE + timedelta(hours=1))
        self._link("url-b-live")
        self._assign(c.id, "url-b-live", assigned_at=NAIVE + timedelta(hours=1))
        self._record("url-b-live", status="activated", owner_client_id=c.id,
                     activated_at=NAIVE + timedelta(hours=2))

        by_slug = {s["slug"]: s for s in self._payload(c.id)["assigned_slugs"]}
        self.assertEqual(by_slug["url-b-legacy"]["activation_state"], "Legacy")
        self.assertIsNone(by_slug["url-b-legacy"]["activation_status"])
        self.assertIsNone(by_slug["url-b-legacy"]["activated_at"])
        self.assertEqual(by_slug["url-b-live"]["activation_state"], "Activated")
        self.assertEqual(by_slug["url-b-live"]["activation_status"], "activated")
        self.assertEqual(by_slug["url-b-live"]["activation_owner_client_id"], c.id)


if __name__ == "__main__":
    unittest.main()
