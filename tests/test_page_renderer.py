"""Regression lock for page_renderer._render_page_html() (Page Engine Phase 4L-A).

Behaviour-preservation tests only -- no DB, no FastAPI, no admin routes.
Uses a lightweight stub in place of models.Page since _render_page_html()
only reads .title / .template_type / .content_json off its argument.
"""
import json
import unittest
from types import SimpleNamespace

from page_renderer import _render_page_html


def make_page(template_type, title="Test Title", content=None):
    content_json = json.dumps(content) if content is not None else None
    return SimpleNamespace(
        title=title,
        template_type=template_type,
        content_json=content_json,
    )


class InvitationTests(unittest.TestCase):
    def test_full_field_set_renders_expected_values(self):
        page = make_page(
            "invitation",
            title="Jane & John",
            content={
                "message": "Join us to celebrate",
                "date": "2026-12-31",
                "time": "18:00",
                "venue": "The Grand Hall",
                "rsvp_contact": "+85512345678",
            },
        )
        out = _render_page_html(page)
        self.assertIn("Join us to celebrate", out)
        self.assertIn("2026-12-31", out)
        self.assertIn("18:00", out)
        self.assertIn("The Grand Hall", out)
        self.assertIn(">RSVP<", out)
        self.assertIn("tel:+85512345678", out)

    def test_missing_optional_fields_omit_facts_and_button(self):
        page = make_page("invitation", content={"message": "Hello"})
        out = _render_page_html(page)
        self.assertIn("Hello", out)
        self.assertNotIn('<div class="fact-row">', out)
        self.assertNotIn(">RSVP<", out)
        self.assertNotIn('<div class="btn-row">', out)


class BrandProductTests(unittest.TestCase):
    def test_full_field_set_renders_expected_values(self):
        page = make_page(
            "brand_product",
            title="Widget Pro",
            content={
                "tagline": "Best widget ever",
                "description": "Full product description",
                "contact": "sales@example.com",
            },
        )
        out = _render_page_html(page)
        self.assertIn("Best widget ever", out)
        self.assertIn("Full product description", out)
        self.assertIn(">Contact<", out)
        self.assertIn("mailto:sales@example.com", out)

    def test_missing_optional_fields_omit_contact_button(self):
        page = make_page("brand_product", content={"tagline": "Just a tagline"})
        out = _render_page_html(page)
        self.assertIn("Just a tagline", out)
        self.assertNotIn(">Contact<", out)
        self.assertNotIn('<div class="btn-row">', out)


class ChildSafetyTests(unittest.TestCase):
    def test_full_field_set_renders_both_contact_actions(self):
        page = make_page(
            "child_safety",
            title="Missing Child Alert",
            content={
                "child_name": "Alex Doe",
                "age": "7",
                "description": "Last seen at the park",
                "contact_name": "Jamie Doe",
                "contact_phone": "+85511112222",
                "contact_phone_2": "+85533334444",
                "notes": "Wearing a red jacket",
            },
        )
        out = _render_page_html(page)
        self.assertIn("Alex Doe", out)
        self.assertIn("Last seen at the park", out)
        self.assertIn("Jamie Doe", out)
        self.assertIn("Wearing a red jacket", out)
        self.assertIn(">Call Now<", out)
        self.assertIn(">Call Alt. Number<", out)
        self.assertIn("tel:+85511112222", out)
        self.assertIn("tel:+85533334444", out)

    def test_missing_optional_fields_omit_rows_and_buttons(self):
        page = make_page("child_safety", content={"child_name": "Alex Doe"})
        out = _render_page_html(page)
        self.assertIn("Alex Doe", out)
        self.assertNotIn(">Call Now<", out)
        self.assertNotIn(">Call Alt. Number<", out)
        self.assertNotIn('<div class="btn-row">', out)
        # Only one fact row (child_name) should exist -- notes are absent so
        # notes-specific markup must not appear at all.
        self.assertNotIn("class=\"notes\"", out)


class MalformedContentTests(unittest.TestCase):
    def test_invalid_json_falls_back_to_empty_data(self):
        page = SimpleNamespace(
            title="Fallback Title",
            template_type="invitation",
            content_json="{not valid json",
        )
        out = _render_page_html(page)
        self.assertIn("Fallback Title", out)
        self.assertIn("<html", out)
        self.assertNotIn('<div class="fact-row">', out)

    def test_non_dict_json_list_falls_back_to_empty_data(self):
        page = make_page("brand_product", content=["not", "a", "dict"])
        out = _render_page_html(page)
        self.assertIn("<html", out)
        self.assertNotIn('<div class="btn-row">', out)

    def test_non_dict_json_string_falls_back_to_empty_data(self):
        page = SimpleNamespace(
            title="String Payload",
            template_type="brand_product",
            content_json=json.dumps("just a string"),
        )
        out = _render_page_html(page)
        self.assertIn("String Payload", out)
        self.assertNotIn('<div class="btn-row">', out)

    def test_non_dict_json_number_falls_back_to_empty_data(self):
        page = SimpleNamespace(
            title="Number Payload",
            template_type="child_safety",
            content_json="42",
        )
        out = _render_page_html(page)
        self.assertIn("Number Payload", out)
        self.assertNotIn('<div class="fact-row">', out)

    def test_non_dict_json_null_falls_back_to_empty_data(self):
        page = SimpleNamespace(
            title="Null Payload",
            template_type="child_safety",
            content_json="null",
        )
        out = _render_page_html(page)
        self.assertIn("Null Payload", out)
        self.assertNotIn('<div class="fact-row">', out)


class UnknownTemplateTypeTests(unittest.TestCase):
    def test_unknown_template_falls_back_to_title_only(self):
        page = make_page(
            "some_future_template",
            title="Unknown Template Page",
            content={"message": "should be ignored"},
        )
        out = _render_page_html(page)
        self.assertIn("Unknown Template Page", out)
        self.assertIn("<html", out)
        self.assertNotIn('<div class="fact-row">', out)
        self.assertNotIn('<div class="btn-row">', out)
        self.assertNotIn("should be ignored", out)


class EscapingTests(unittest.TestCase):
    def test_title_is_escaped(self):
        page = make_page("invitation", title="<script>alert(1)</script>")
        out = _render_page_html(page)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_content_values_are_escaped(self):
        page = make_page(
            "brand_product",
            title="Safe Title",
            content={
                "tagline": "<img src=x onerror=alert(1)>",
                "description": "5 < 10 & 10 > 5",
            },
        )
        out = _render_page_html(page)
        self.assertNotIn("<img src=x onerror=alert(1)>", out)
        self.assertIn("&lt;img", out)
        self.assertIn("&amp;", out)


if __name__ == "__main__":
    unittest.main()
