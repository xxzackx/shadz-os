"""Regression tests for the Activation Engine v1 Phase A2 production
integration gap: creating a url/media slug through the Link Engine admin
routes must also create its ActivationRecord, so the public Activation
Gateway (link_public.resolve_activation_redirect) can trigger.

Covers both slug-creation paths in link_admin.py:
  - POST /admin/link        (create_link — auto-generated slug)
  - POST /admin/link/{slug} (upsert_link — new-slug branch)

Uses a dedicated FastAPI app registering only the Link Engine admin routes,
with get_db overridden to an isolated in-memory SQLite database (matching
tests/test_page_admin.py's pattern) — never touches the real shadz.db.
"""
import os
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_runtime
import link_admin
import models
from database import Base, get_db
from link_admin import _generate_activation_token, register_link_admin_routes

# Matches bot_runtime._START_PAYLOAD_RE's allowed charset for the token
# portion of "activate_<token>" — proves generated tokens are Telegram-safe.
_TELEGRAM_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class LinkAdminActivationWiringTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        # raise_server_exceptions=False: needed for the atomic-rollback test
        # below to inspect a genuine 500 response instead of the exception
        # propagating into the test itself. HTTPException-based responses
        # (400/404/409/201 etc, used by every other test here) are handled
        # by FastAPI's own exception handler and are unaffected by this flag.
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _activation_record_for(self, slug):
        return (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == slug)
            .first()
        )

    # ── POST /admin/link (auto-generated slug) ──────────────────────────────

    def test_create_url_link_creates_activation_record(self):
        response = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com",
                "phone_number": "555-0100",
            },
        )
        self.assertEqual(response.status_code, 201)
        slug = response.json()["slug"]

        record = self._activation_record_for(slug)
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertTrue(_TELEGRAM_SAFE_TOKEN_RE.match(record.activation_token))

    def test_create_media_link_creates_activation_record(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "media", "phone_number": "555-0101"},
        )
        self.assertEqual(response.status_code, 201)
        slug = response.json()["slug"]

        record = self._activation_record_for(slug)
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_create_page_link_does_not_create_activation_record(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "page", "phone_number": "555-0102"},
        )
        self.assertEqual(response.status_code, 201)
        slug = response.json()["slug"]

        self.assertIsNone(self._activation_record_for(slug))

    def test_two_created_url_links_get_distinct_activation_tokens(self):
        r1 = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/a",
                "phone_number": "555-0103",
            },
        )
        r2 = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/b",
                "phone_number": "555-0104",
            },
        )
        token1 = self._activation_record_for(r1.json()["slug"]).activation_token
        token2 = self._activation_record_for(r2.json()["slug"]).activation_token
        self.assertNotEqual(token1, token2)

    # ── POST /admin/link/{slug} (upsert — new-slug branch) ──────────────────

    def test_upsert_new_url_slug_creates_activation_record(self):
        response = self.client.post(
            "/admin/link/url-abc123",
            json={
                "destination_url": "https://example.com",
                "phone_number": "555-0105",
            },
        )
        self.assertEqual(response.status_code, 200)

        record = self._activation_record_for("url-abc123")
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_upsert_new_media_slug_creates_activation_record(self):
        # upsert_link requires a non-empty destination_url for any new slug,
        # regardless of content_type — matches existing endpoint behaviour.
        response = self.client.post(
            "/admin/link/media-xyz789",
            json={"destination_url": "https://example.com", "phone_number": "555-0106"},
        )
        self.assertEqual(response.status_code, 200)

        record = self._activation_record_for("media-xyz789")
        self.assertIsNotNone(record)

    def test_upsert_new_page_slug_does_not_create_activation_record(self):
        response = self.client.post(
            "/admin/link/page-def456",
            json={"destination_url": "https://example.com", "phone_number": "555-0107"},
        )
        self.assertEqual(response.status_code, 200)

        self.assertIsNone(self._activation_record_for("page-def456"))

    def test_upsert_existing_slug_update_does_not_create_activation_record(self):
        # First call creates the slug (and its ActivationRecord).
        self.client.post(
            "/admin/link/url-existg",
            json={"destination_url": "https://example.com", "phone_number": "555-0108"},
        )
        # Second call updates the same slug — must not create a second record
        # or otherwise touch the existing one.
        response = self.client.post(
            "/admin/link/url-existg",
            json={"destination_url": "https://example.com/updated"},
        )
        self.assertEqual(response.status_code, 200)

        records = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "url-existg")
            .all()
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].activation_status, "unactivated")

    def test_failed_create_leaves_no_orphaned_rows(self):
        # A request rejected before the RedirectLink is ever added (missing
        # phone_number) must leave neither a RedirectLink nor an
        # ActivationRecord behind.
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "destination_url": "https://example.com"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.db.query(models.RedirectLink).count(), 0)
        self.assertEqual(self.db.query(models.ActivationRecord).count(), 0)


class GenerateActivationTokenTests(unittest.TestCase):
    """Focused tests proving _generate_activation_token's tokens satisfy
    the existing Phase A2 validator (bot_runtime._build_activation_payload /
    build_activation_deep_link), and that its retry loop is bounded — never
    an unbounded `while True`."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_token_is_non_empty(self):
        token = _generate_activation_token(self.db)
        self.assertTrue(token)

    def test_token_contains_only_allowed_characters(self):
        token = _generate_activation_token(self.db)
        self.assertRegex(token, _TELEGRAM_SAFE_TOKEN_RE)

    def test_activation_payload_is_at_most_64_utf8_bytes(self):
        token = _generate_activation_token(self.db)
        payload = f"activate_{token}"
        self.assertLessEqual(len(payload.encode("utf-8")), 64)

    def test_token_passes_build_activation_payload(self):
        token = _generate_activation_token(self.db)
        payload = bot_runtime._build_activation_payload(token)
        self.assertEqual(payload, f"activate_{token}")

    def test_token_produces_valid_deep_link_with_configured_username(self):
        token = _generate_activation_token(self.db)
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"}):
            link = bot_runtime.build_activation_deep_link(token)
        self.assertEqual(link, f"https://t.me/shadz_test_bot?start=activate_{token}")

    def test_two_generated_tokens_are_distinct(self):
        token1 = _generate_activation_token(self.db)
        token2 = _generate_activation_token(self.db)
        self.assertNotEqual(token1, token2)

    def test_forced_collision_retries_and_eventually_succeeds(self):
        # Seed a real ActivationRecord using the "colliding" token so the
        # collision check inside _generate_activation_token is genuine.
        link = models.RedirectLink(slug="url-collid", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="url-collid", activation_token="dup-token"))
        self.db.commit()

        with patch.object(
            link_admin.secrets, "token_urlsafe",
            side_effect=["dup-token", "dup-token", "unique-token"],
        ) as mock_gen:
            token = _generate_activation_token(self.db)

        self.assertEqual(token, "unique-token")
        self.assertEqual(mock_gen.call_count, 3)

    def test_repeated_collisions_fail_safely_with_bounded_retries(self):
        link = models.RedirectLink(slug="url-collid", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="url-collid", activation_token="always-dup"))
        self.db.commit()

        with patch.object(
            link_admin.secrets, "token_urlsafe", return_value="always-dup",
        ) as mock_gen:
            with self.assertRaises(HTTPException) as ctx:
                _generate_activation_token(self.db)

        self.assertEqual(ctx.exception.status_code, 500)
        # Bounded: exactly 10 attempts, not an unbounded loop.
        self.assertEqual(mock_gen.call_count, 10)


class ProvisioningInvariantTests(unittest.TestCase):
    """Focused tests proving the exact shape of what gets provisioned (and
    what doesn't) by each of the two admin creation routes."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _record_for(self, slug):
        return (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == slug)
            .first()
        )

    def _assert_clean_invariants(self, slug):
        records = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == slug)
            .all()
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_url_creation_creates_exactly_one_activation_record(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "destination_url": "https://example.com", "phone_number": "555-0200"},
        )
        self.assertEqual(response.status_code, 201)
        self._assert_clean_invariants(response.json()["slug"])

    def test_media_creation_creates_exactly_one_activation_record(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "media", "phone_number": "555-0201"},
        )
        self.assertEqual(response.status_code, 201)
        self._assert_clean_invariants(response.json()["slug"])

    def test_page_creation_creates_none(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "page", "phone_number": "555-0202"},
        )
        self.assertEqual(response.status_code, 201)
        slug = response.json()["slug"]
        self.assertEqual(
            self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).count(),
            0,
        )

    def test_second_route_behaves_identically(self):
        # POST /admin/link/{slug} (upsert new-slug branch) must produce the
        # exact same invariants as POST /admin/link.
        response = self.client.post(
            "/admin/link/url-second",
            json={"destination_url": "https://example.com", "phone_number": "555-0203"},
        )
        self.assertEqual(response.status_code, 200)
        self._assert_clean_invariants("url-second")

    def test_updating_existing_slug_does_not_create_duplicate_record(self):
        self.client.post(
            "/admin/link/url-updscn",
            json={"destination_url": "https://example.com", "phone_number": "555-0204"},
        )
        response = self.client.post(
            "/admin/link/url-updscn",
            json={"destination_url": "https://example.com/updated"},
        )
        self.assertEqual(response.status_code, 200)
        self._assert_clean_invariants("url-updscn")

    def test_duplicate_creation_cannot_produce_two_records_for_one_slug(self):
        # DB-level guarantee (ck/unique constraint from Phase A1): a second
        # ActivationRecord for the same slug is rejected even if application
        # code somehow attempted it.
        link = models.RedirectLink(slug="url-dupe01", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        models.create_activation_record_for_slug(self.db, "url-dupe01", "tok-first")
        self.db.commit()

        with self.assertRaises(IntegrityError):
            models.create_activation_record_for_slug(self.db, "url-dupe01", "tok-second")
            self.db.commit()
        self.db.rollback()

        self.assertEqual(
            self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "url-dupe01").count(),
            1,
        )


class AtomicRollbackTests(unittest.TestCase):
    """Proves that a failure between db.flush() (RedirectLink staged) and
    db.commit() (ActivationRecord creation) leaves no trace of either row —
    the request fails safely, with no partial commit and no false success."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_create_link_rolls_back_on_activation_record_failure(self):
        with patch.object(
            models, "create_activation_record_for_slug",
            side_effect=RuntimeError("forced failure after RedirectLink flush"),
        ):
            response = self.client.post(
                "/admin/link",
                json={"content_type": "url", "destination_url": "https://example.com", "phone_number": "555-0300"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.db.query(models.RedirectLink).count(), 0)
        self.assertEqual(self.db.query(models.ActivationRecord).count(), 0)

    def test_upsert_new_slug_rolls_back_on_activation_record_failure(self):
        with patch.object(
            models, "create_activation_record_for_slug",
            side_effect=RuntimeError("forced failure after RedirectLink flush"),
        ):
            response = self.client.post(
                "/admin/link/url-rollbk",
                json={"destination_url": "https://example.com", "phone_number": "555-0301"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "url-rollbk").count(), 0
        )
        self.assertEqual(
            self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "url-rollbk").count(), 0
        )


if __name__ == "__main__":
    unittest.main()
