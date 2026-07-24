"""Regression tests for the Activation Engine v1 Phase A1 data foundation.

Covers the ActivationRecord model (defaults, unique constraints, nullable
fields) and the delete_activation_lifecycle_for_slug cleanup helper. Uses an
isolated in-memory SQLite database — never touches the real shadz.db. Also
confirms existing url/media/page dispatch fields are untouched by this phase.
"""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import models
from database import Base


class ActivationRecordModelTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_link(self, slug="abc123", content_type="url"):
        link = models.RedirectLink(
            slug=slug, destination_url="https://example.com", content_type=content_type
        )
        self.db.add(link)
        self.db.commit()
        return link

    def test_activation_table_created(self):
        self.assertIn("activation_records", Base.metadata.tables)

    def test_default_status_is_unactivated(self):
        self._make_link()
        record = models.ActivationRecord(slug="abc123", activation_token="tok-1")
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_owner_and_activated_at_nullable_before_activation(self):
        self._make_link()
        record = models.ActivationRecord(slug="abc123", activation_token="tok-1")
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)

    def test_invalid_activation_status_rejected_by_database(self):
        self._make_link()
        record = models.ActivationRecord(
            slug="abc123", activation_token="tok-1", activation_status="bogus"
        )
        self.db.add(record)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_can_transition_to_activated(self):
        self._make_link()
        record = models.ActivationRecord(slug="abc123", activation_token="tok-1")
        self.db.add(record)
        self.db.commit()

        record.activation_status = "activated"
        record.owner_client_id = None
        record.activated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(record)
        self.assertEqual(record.activation_status, "activated")
        self.assertIsNotNone(record.activated_at)

    def test_slug_must_be_unique(self):
        self._make_link()
        self.db.add(models.ActivationRecord(slug="abc123", activation_token="tok-1"))
        self.db.commit()

        self.db.add(models.ActivationRecord(slug="abc123", activation_token="tok-2"))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_activation_token_must_be_unique(self):
        self._make_link(slug="abc123")
        self._make_link(slug="def456")
        self.db.add(models.ActivationRecord(slug="abc123", activation_token="dup-token"))
        self.db.commit()

        self.db.add(models.ActivationRecord(slug="def456", activation_token="dup-token"))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()


class CreateActivationRecordForSlugTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_link(self, slug, content_type):
        link = models.RedirectLink(
            slug=slug, destination_url="https://example.com", content_type=content_type
        )
        self.db.add(link)
        self.db.commit()
        return link

    def test_url_slug_creates_activation_record(self):
        self._make_link("u1", "url")
        record = models.create_activation_record_for_slug(self.db, "u1", "tok-u1")
        self.assertEqual(record.slug, "u1")
        self.assertEqual(record.activation_token, "tok-u1")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)

    def test_media_slug_creates_activation_record(self):
        self._make_link("m1", "media")
        record = models.create_activation_record_for_slug(self.db, "m1", "tok-m1")
        self.assertEqual(record.slug, "m1")
        self.assertEqual(record.activation_status, "unactivated")

    def test_page_slug_is_rejected(self):
        self._make_link("p1", "page")
        with self.assertRaises(ValueError):
            models.create_activation_record_for_slug(self.db, "p1", "tok-p1")

    def test_nonexistent_slug_is_rejected(self):
        with self.assertRaises(ValueError):
            models.create_activation_record_for_slug(self.db, "no-such-slug", "tok-x")

    def test_helper_does_not_commit_automatically(self):
        # If the helper committed internally, a rollback afterward could not
        # undo the insert. Proving the row disappears on rollback (rather
        # than surviving it) demonstrates the transaction was never
        # committed by the helper itself. A cross-session visibility check
        # is not used here because SQLAlchemy's SQLite ":memory:" pooling
        # shares the same underlying connection across sessions in a single
        # thread, which would make that style of check unreliable.
        self._make_link("u2", "url")
        models.create_activation_record_for_slug(self.db, "u2", "tok-u2")

        self.db.rollback()

        still_present = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "u2")
            .first()
        )
        self.assertIsNone(still_present)


class ActivationLifecycleCleanupTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _seed_activated_slug_with_bot_client(self, slug="abc123"):
        link = models.RedirectLink(
            slug=slug, destination_url="https://example.com", content_type="url"
        )
        client = models.BotClient(client_name="Test Client", access_code="ABC123")
        self.db.add_all([link, client])
        self.db.commit()

        assignment = models.BotClientSlug(bot_client_id=client.id, slug=slug)
        record = models.ActivationRecord(
            slug=slug,
            activation_status="activated",
            activation_token="tok-1",
            owner_client_id=client.id,
            activated_at=datetime.now(timezone.utc),
        )
        self.db.add_all([assignment, record])
        self.db.commit()
        return link, client

    def test_deletes_activation_record_for_slug(self):
        self._seed_activated_slug_with_bot_client()
        models.delete_activation_lifecycle_for_slug(self.db, "abc123")
        self.db.commit()

        remaining = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "abc123")
            .first()
        )
        self.assertIsNone(remaining)

    def test_deletes_bot_client_slug_assignment_for_slug(self):
        self._seed_activated_slug_with_bot_client()
        models.delete_activation_lifecycle_for_slug(self.db, "abc123")
        self.db.commit()

        remaining = (
            self.db.query(models.BotClientSlug)
            .filter(models.BotClientSlug.slug == "abc123")
            .first()
        )
        self.assertIsNone(remaining)

    def test_bot_client_row_survives_cleanup(self):
        _, client = self._seed_activated_slug_with_bot_client()
        models.delete_activation_lifecycle_for_slug(self.db, "abc123")
        self.db.commit()

        survivor = (
            self.db.query(models.BotClient).filter(models.BotClient.id == client.id).first()
        )
        self.assertIsNotNone(survivor)

    def test_cleanup_is_a_safe_noop_for_unrelated_slug(self):
        self._seed_activated_slug_with_bot_client(slug="abc123")
        # Should not raise or affect unrelated rows when nothing matches.
        models.delete_activation_lifecycle_for_slug(self.db, "nonexistent-slug")
        self.db.commit()

        still_present = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "abc123")
            .first()
        )
        self.assertIsNotNone(still_present)


class ExistingDispatchUntouchedTests(unittest.TestCase):
    """Confirms Phase A1 does not alter url/media/page redirect_links fields."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_url_media_page_links_unaffected_by_activation_table(self):
        url_link = models.RedirectLink(
            slug="u1", destination_url="https://example.com/u", content_type="url"
        )
        media_link = models.RedirectLink(
            slug="m1", destination_url="https://example.com/m", content_type="media"
        )
        page_link = models.RedirectLink(
            slug="p1", destination_url="https://example.com/p", content_type="page"
        )
        self.db.add_all([url_link, media_link, page_link])
        self.db.commit()

        for slug, expected_type in (("u1", "url"), ("m1", "media"), ("p1", "page")):
            link = (
                self.db.query(models.RedirectLink)
                .filter(models.RedirectLink.slug == slug)
                .first()
            )
            self.assertEqual(link.content_type, expected_type)
            # No activation record exists unless explicitly created.
            record = (
                self.db.query(models.ActivationRecord)
                .filter(models.ActivationRecord.slug == slug)
                .first()
            )
            self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
