import html
import json

import models


def _render_page_html(page: "models.Page") -> str:
    """Render a safe public HTML page from a Page ORM object.

    All user-controlled text is HTML-escaped before insertion.
    content_json is parsed as a dict; parse errors and unknown keys are ignored.
    """
    safe_title = html.escape(page.title)

    data: dict = {}
    if page.content_json:
        try:
            parsed = json.loads(page.content_json)
            if isinstance(parsed, dict):
                data = parsed
        except (ValueError, TypeError):
            pass

    def _e(key: str) -> str:
        val = data.get(key)
        return html.escape(str(val)) if val else ""

    tt = page.template_type

    if tt == "invitation":
        msg = _e("message")
        msg_block = f'<p class="msg">{msg}</p>' if msg else ""
        rows = ""
        for label, key in [("Date", "date"), ("Time", "time"),
                            ("Venue", "venue"), ("RSVP", "rsvp_contact")]:
            val = _e(key)
            if val:
                rows += f'<tr><td class="lbl">{label}</td><td>{val}</td></tr>'
        table = f'<table>{rows}</table>' if rows else ""
        inner = (
            f'<p class="eyebrow">You are invited</p>'
            f'<h1>{safe_title}</h1>'
            f'{msg_block}{table}'
        )

    elif tt == "brand_product":
        tagline    = _e("tagline")
        desc       = _e("description")
        contact    = _e("contact")
        tagline_b  = f'<p class="tagline">{tagline}</p>' if tagline else ""
        desc_b     = f'<p class="desc">{desc}</p>' if desc else ""
        contact_b  = f'<p class="contact">{contact}</p>' if contact else ""
        inner = f'<h1>{safe_title}</h1>{tagline_b}{desc_b}{contact_b}'

    elif tt == "child_safety":
        rows = ""
        for label, key in [
            ("Name", "child_name"), ("Age", "age"),
            ("Last seen", "description"),
            ("Contact", "contact_name"), ("Phone", "contact_phone"),
            ("Alt phone", "contact_phone_2"), ("Notes", "notes"),
        ]:
            val = _e(key)
            if val:
                rows += f'<tr><td class="lbl">{label}</td><td>{val}</td></tr>'
        table = f'<table>{rows}</table>' if rows else ""
        inner = (
            f'<p class="eyebrow alert-eye">Missing Child</p>'
            f'<h1>{safe_title}</h1>'
            f'{table}'
            f'<p class="help-note">If you have information, please contact immediately.</p>'
        )

    else:
        inner = f'<h1>{safe_title}</h1>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{safe_title}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#d4d0c8;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:2rem;
         font-family:system-ui,sans-serif}}
    .wordmark{{position:fixed;top:1rem;left:50%;transform:translateX(-50%);
               font-size:.65rem;letter-spacing:.25em;text-transform:uppercase;color:#2a2520}}
    .card{{max-width:480px;width:100%;text-align:center}}
    .eyebrow{{font-size:.65rem;letter-spacing:.2em;text-transform:uppercase;
              color:#7a5f28;margin-bottom:1.2rem}}
    .alert-eye{{color:#c9a84c}}
    h1{{font-size:1.4rem;font-weight:600;letter-spacing:.04em;
        color:#e8e0d0;margin-bottom:1.2rem;line-height:1.3}}
    .msg{{font-size:.9rem;color:#a09888;line-height:1.7;margin-bottom:1.5rem}}
    .tagline{{font-size:.8rem;letter-spacing:.15em;text-transform:uppercase;
              color:#c9a84c;margin-bottom:1rem}}
    .desc{{font-size:.9rem;color:#a09888;line-height:1.7;margin-bottom:1rem}}
    .contact{{font-size:.85rem;color:#d4d0c8;margin-top:.5rem}}
    .help-note{{font-size:.75rem;color:#7a5f28;margin-top:1.5rem;
                letter-spacing:.05em;line-height:1.6}}
    table{{width:100%;border-collapse:collapse;margin-top:1rem;text-align:left}}
    td{{padding:.5rem .4rem;font-size:.85rem;border-bottom:1px solid #1a1614;
        vertical-align:top}}
    td.lbl{{color:#7a5f28;font-size:.7rem;letter-spacing:.1em;
            text-transform:uppercase;width:30%;white-space:nowrap}}
  </style>
</head>
<body>
  <div class="wordmark">SHADZ</div>
  <div class="card">{inner}</div>
</body>
</html>"""
