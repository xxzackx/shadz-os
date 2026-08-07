"""Regression tests for Activation Engine v1 — Production Hotfix H1A
(Unassign lifecycle consistency).

Covers bot_admin.remove_slug_assignment (admin "Unassign" button, wired to
DELETE /admin/bot/clients/{client_id}/slugs/{slug}):

  - URL slug unassign resets ActivationRecord to unactivated (owner and
    activated_at cleared, activation_token preserved) and clears
    destination_url, in addition to removing the BotClientSlug row.
  - Media slug unassign does the same ActivationRecord reset and deactivates
    the current active SlugMedia row, without deleting the MediaAsset row.
  - A slug with no ActivationRecord (not activation-enabled) is unaffected
    beyond the assignment removal — no crash, no ActivationRecord created.
  - Failure mid-transaction (simulated commit failure) leaves no partial
    state: assignment, ActivationRecord, destination_url, and SlugMedia are
    all unchanged.

Uses a dedicated FastAPI app registering only the Bot Engine admin routes,
with get_db overridden to an isolated in-memory SQLite database (matching
tests/test_link_admin_activation.py's pattern) — never touches the real
shadz.db.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from bot_admin import register_bot_admin_routes
from database import Base, get_db


class UnassignLifecycleTests(unittest.TestCase):
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
        register_bot_admin_routes(router)
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

    # ── seeding helpers ──────────────────────────────────────────────────

    def _make_bot_client(self):
        client = models.BotClient(client_name="Test Client", access_code="ABC123")
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        return client

    def _make_url_slug(self, slug="myurl", destination="https://example.com/original"):
        link = models.RedirectLink(
            slug=slug, destination_url=destination, content_type="url"
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _make_media_slug(self, slug="mymedia"):
        link = models.RedirectLink(slug=slug, destination_url="", content_type="media")
        self.db.add(link)
        asset = models.MediaAsset(
            media_type="image",
            storage_key="k1",
            public_url="https://media.shadz.io/k1",
            original_filename="a.png",
            mime_type="image/png",
            file_size=100,
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        sm = models.SlugMedia(slug=slug, media_asset_id=asset.id, is_active=True)
        self.db.add(sm)
        self.db.commit()
        self.db.refresh(sm)
        return link, asset, sm

    def _make_activation_record(self, slug, activated=True, owner_id=None):
        from datetime import datetime, timezone

        record = models.ActivationRecord(
            slug=slug,
            activation_status="activated" if activated else "unactivated",
            activation_token=f"tok-{slug}",
            owner_client_id=owner_id,
            activated_at=datetime.now(timezone.utc) if activated else None,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def _assign(self, client_id, slug):
        assignment = models.BotClientSlug(bot_client_id=client_id, slug=slug)
        self.db.add(assignment)
        self.db.commit()
        return assignment

    def _activation_record_for(self, slug):
        return (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == slug)
            .first()
        )

    def _assignment_for(self, slug):
        return (
            self.db.query(models.BotClientSlug)
            .filter(models.BotClientSlug.slug == slug)
            .first()
        )

    # ── URL slug unassign ────────────────────────────────────────────────

    def test_url_unassign_resets_activation_and_clears_destination(self):
        client = self._make_bot_client()
        self._make_url_slug("myurl", "https://example.com/original")
        self._make_activation_record("myurl", activated=True, owner_id=client.id)
        self._assign(client.id, "myurl")

        resp = self.client.delete(f"/admin/bot/clients/{client.id}/slugs/myurl")
        self.assertEqual(resp.status_code, 200, resp.text)

        self.assertIsNone(self._assignment_for("myurl"))

        record = self._activation_record_for("myurl")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertEqual(record.activation_token, "tok-myurl")

        link = self.db.query(models.RedirectLink).filter(
            models.RedirectLink.slug == "myurl"
        ).first()
        self.assertEqual(link.destination_url, "")

    # ── Media slug unassign ──────────────────────────────────────────────

    def test_media_unassign_resets_activation_and_deactivates_slug_media(self):
        client = self._make_bot_client()
        link, asset, sm = self._make_media_slug("mymedia")
        self._make_activation_record("mymedia", activated=True, owner_id=client.id)
        self._assign(client.id, "mymedia")

        resp = self.client.delete(f"/admin/bot/clients/{client.id}/slugs/mymedia")
        self.assertEqual(resp.status_code, 200, resp.text)

        self.assertIsNone(self._assignment_for("mymedia"))

        record = self._activation_record_for("mymedia")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertEqual(record.activation_token, "tok-mymedia")

        self.db.refresh(sm)
        self.assertFalse(sm.is_active)

        # MediaAsset row must be preserved (H1A cleanup boundary).
        preserved_asset = (
            self.db.query(models.MediaAsset).filter(models.MediaAsset.id == asset.id).first()
        )
        self.assertIsNotNone(preserved_asset)
        self.assertFalse(preserved_asset.is_deleted)

    # ── Non-activation slug is unaffected beyond assignment removal ──────

    def test_unassign_without_activation_record_only_removes_assignment(self):
        client = self._make_bot_client()
        self._make_url_slug("plainurl", "https://example.com/plain")
        self._assign(client.id, "plainurl")

        resp = self.client.delete(f"/admin/bot/clients/{client.id}/slugs/plainurl")
        self.assertEqual(resp.status_code, 200, resp.text)

        self.assertIsNone(self._assignment_for("plainurl"))
        self.assertIsNone(self._activation_record_for("plainurl"))

        link = self.db.query(models.RedirectLink).filter(
            models.RedirectLink.slug == "plainurl"
        ).first()
        self.assertEqual(link.destination_url, "https://example.com/plain")

    # ── Atomic failure safety: no partial state on commit failure ────────

    def test_failed_commit_leaves_no_partial_state(self):
        client = self._make_bot_client()
        self._make_url_slug("failurl", "https://example.com/original")
        self._make_activation_record("failurl", activated=True, owner_id=client.id)
        self._assign(client.id, "failurl")

        simulated_error = IntegrityError("boom statement", {}, Exception("boom"))
        with patch("sqlalchemy.orm.Session.commit", side_effect=simulated_error):
            resp = self.client.delete(f"/admin/bot/clients/{client.id}/slugs/failurl")
        self.assertEqual(resp.status_code, 500)

        # Re-query with a fresh session to bypass any in-memory staleness.
        fresh_db = self.SessionLocal()
        try:
            assignment = (
                fresh_db.query(models.BotClientSlug)
                .filter(models.BotClientSlug.slug == "failurl")
                .first()
            )
            self.assertIsNotNone(assignment)

            record = (
                fresh_db.query(models.ActivationRecord)
                .filter(models.ActivationRecord.slug == "failurl")
                .first()
            )
            self.assertEqual(record.activation_status, "activated")
            self.assertEqual(record.owner_client_id, client.id)
            self.assertIsNotNone(record.activated_at)

            link = (
                fresh_db.query(models.RedirectLink)
                .filter(models.RedirectLink.slug == "failurl")
                .first()
            )
            self.assertEqual(link.destination_url, "https://example.com/original")
        finally:
            fresh_db.close()


if __name__ == "__main__":
    unittest.main()
