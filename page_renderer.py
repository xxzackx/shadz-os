import html
import json
import re

import models


_PHONE_RE = re.compile(r'^\+?\d{5,15}$')
_PHONE_CHARS_RE = re.compile(r'^[\d+\-\s()]+$')
_EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
_URL_RE = re.compile(r'^https?://\S+$')


def _contact_href(raw: str) -> str:
    """Return a safe href (tel:/mailto:/http(s):) for a freeform contact
    string, or "" if it doesn't match a known safe pattern.

    Values already prefixed with "mailto:" or "tel:" are normalized
    against that scheme rather than re-prefixed. A tel: link is only
    produced when the original value consists solely of phone-number
    characters (digits, +, -, spaces, parentheses) -- URL-like strings
    such as "wa.me/..." or "t.me/..." are never reclassified as phones.
    """
    s = raw.strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith("mailto:"):
        addr = s[len("mailto:"):].strip()
        return html.escape(f"mailto:{addr}", quote=True) if _EMAIL_RE.match(addr) else ""
    if low.startswith("tel:"):
        digits = re.sub(r"[^\d+]", "", s[len("tel:"):])
        return html.escape(f"tel:{digits}", quote=True) if _PHONE_RE.match(digits) else ""
    if _URL_RE.match(s):
        return html.escape(s, quote=True)
    if _EMAIL_RE.match(s):
        return html.escape(f"mailto:{s}", quote=True)
    if _PHONE_CHARS_RE.match(s):
        digits = re.sub(r"[^\d+]", "", s)
        if _PHONE_RE.match(digits):
            return html.escape(f"tel:{digits}", quote=True)
    return ""


_BASE_CSS = """
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#0a0908;color:#d4d0c8;min-height:100vh;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
         -webkit-font-smoothing:antialiased;line-height:1.5}
    .wordmark{position:fixed;top:.9rem;left:50%;transform:translateX(-50%);
              font-size:.6rem;letter-spacing:.3em;text-transform:uppercase;
              color:#2a2520;pointer-events:none;z-index:1}
    .page{min-height:100vh;display:flex;align-items:center;justify-content:center;
          padding:4.5rem 1.1rem 2.5rem}
    .card{max-width:480px;width:100%;background:linear-gradient(180deg,#141210,#0d0c0a);
          border:1px solid #221e18;border-radius:16px;padding:2rem 1.5rem;
          box-shadow:0 20px 60px -20px rgba(0,0,0,.6);text-align:center}
    .eyebrow{display:inline-block;font-size:.65rem;font-weight:600;letter-spacing:.2em;
             text-transform:uppercase;color:#a4813a;margin-bottom:1rem}
    h1{font-size:1.5rem;font-weight:600;letter-spacing:.01em;
       color:#f0e9d8;margin-bottom:1.1rem;line-height:1.35;
       overflow-wrap:break-word;word-break:break-word}
    .divider{width:36px;height:2px;background:#7a5f28;border:0;
             margin:0 auto 1.3rem;border-radius:2px}
    .msg{font-size:.92rem;color:#a89f8e;line-height:1.75;margin-bottom:1.4rem;
         overflow-wrap:break-word;word-break:break-word;white-space:pre-line}
    .desc{font-size:.92rem;color:#a89f8e;line-height:1.75;margin-bottom:1.2rem;
          overflow-wrap:break-word;word-break:break-word;white-space:pre-line}
    .tagline{font-size:.78rem;font-weight:600;letter-spacing:.14em;text-transform:uppercase;
             color:#c9a84c;margin-bottom:.9rem}
    .fact-card{background:#100e0c;border:1px solid #1e1a15;border-radius:12px;
               padding:.3rem 1rem;margin-bottom:1.3rem;text-align:left}
    .fact-row{display:flex;justify-content:space-between;gap:1rem;
              padding:.75rem 0;border-bottom:1px solid #1a1614}
    .fact-row:last-child{border-bottom:none}
    .fact-lbl{font-size:.65rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
              color:#7a6a48;white-space:nowrap;flex-shrink:0;padding-top:.1rem}
    .fact-val{font-size:.9rem;color:#e2ddd0;text-align:right;
              overflow-wrap:break-word;word-break:break-word;min-width:0}
    .btn-row{display:flex;flex-direction:column;gap:.65rem;margin-top:.3rem}
    .btn{display:block;width:100%;min-height:48px;padding:.85rem 1.2rem;
         border-radius:10px;font-size:.9rem;font-weight:600;letter-spacing:.03em;
         text-decoration:none;text-align:center;overflow-wrap:break-word;
         word-break:break-word;border:1px solid transparent;transition:opacity .15s}
    .btn:active{opacity:.8}
    .btn-primary{background:linear-gradient(180deg,#d4b25a,#b8933c);color:#161208}
    .btn-secondary{background:transparent;border-color:#3a3226;color:#d9cba6}
    .help-note{font-size:.76rem;color:#8a7a52;margin-top:1.4rem;
               letter-spacing:.03em;line-height:1.65}
    .notes{font-size:.82rem;color:#8f8676;line-height:1.65;margin-top:1rem;
           text-align:left;overflow-wrap:break-word;word-break:break-word}
    @media (max-width:400px){
      .card{padding:1.6rem 1.1rem;border-radius:13px}
      h1{font-size:1.3rem}
    }
"""

_ALERT_CSS = """
    .alert-badge{display:inline-flex;align-items:center;gap:.4rem;font-size:.68rem;
                 font-weight:700;letter-spacing:.16em;text-transform:uppercase;
                 color:#e0b94a;background:rgba(224,185,74,.08);
                 border:1px solid rgba(224,185,74,.35);border-radius:999px;
                 padding:.4rem .9rem;margin-bottom:1.1rem}
    .alert-badge::before{content:"";width:6px;height:6px;border-radius:50%;
                          background:#e0b94a;flex-shrink:0}
"""


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

    def _raw(key: str) -> str:
        val = data.get(key)
        return str(val).strip() if val else ""

    def _e(key: str) -> str:
        val = _raw(key)
        return html.escape(val) if val else ""

    def _fact_rows(fields) -> str:
        rows = ""
        for label, key in fields:
            val = _e(key)
            if val:
                rows += (
                    f'<div class="fact-row"><span class="fact-lbl">{label}</span>'
                    f'<span class="fact-val">{val}</span></div>'
                )
        return f'<div class="fact-card">{rows}</div>' if rows else ""

    def _contact_button(key: str, label: str, primary: bool) -> str:
        raw = _raw(key)
        if not raw:
            return ""
        cls = "btn-primary" if primary else "btn-secondary"
        href = _contact_href(raw)
        text = html.escape(raw)
        if href:
            return f'<a class="btn {cls}" href="{href}">{label}</a>'
        return f'<div class="btn {cls}" role="text">{text}</div>'

    extra_css = ""

    tt = page.template_type

    if tt == "invitation":
        msg = _e("message")
        msg_block = f'<p class="msg">{msg}</p>' if msg else ""
        facts = _fact_rows([("Date", "date"), ("Time", "time"), ("Venue", "venue")])
        rsvp_btn = _contact_button("rsvp_contact", "RSVP", primary=True)
        btn_row = f'<div class="btn-row">{rsvp_btn}</div>' if rsvp_btn else ""
        inner = (
            f'<p class="eyebrow">You are invited</p>'
            f'<h1>{safe_title}</h1>'
            f'<hr class="divider">'
            f'{msg_block}{facts}{btn_row}'
        )

    elif tt == "brand_product":
        tagline = _e("tagline")
        desc = _e("description")
        tagline_b = f'<p class="tagline">{tagline}</p>' if tagline else ""
        desc_b = f'<p class="desc">{desc}</p>' if desc else ""
        contact_btn = _contact_button("contact", "Contact", primary=True)
        btn_row = f'<div class="btn-row">{contact_btn}</div>' if contact_btn else ""
        inner = f'{tagline_b}<h1>{safe_title}</h1><hr class="divider">{desc_b}{btn_row}'

    elif tt == "child_safety":
        extra_css = _ALERT_CSS
        facts = _fact_rows([
            ("Name", "child_name"), ("Age", "age"),
            ("Last seen", "description"), ("Contact", "contact_name"),
            ("Phone", "contact_phone"), ("Alt phone", "contact_phone_2"),
        ])
        call_btn = _contact_button("contact_phone", "Call Now", primary=True)
        call_btn_2 = _contact_button("contact_phone_2", "Call Alt. Number", primary=False)
        btn_row = f'<div class="btn-row">{call_btn}{call_btn_2}</div>' if (call_btn or call_btn_2) else ""
        notes = _e("notes")
        notes_b = f'<p class="notes">{notes}</p>' if notes else ""
        inner = (
            f'<span class="alert-badge">Missing Child</span>'
            f'<h1>{safe_title}</h1>'
            f'<hr class="divider">'
            f'{facts}{btn_row}{notes_b}'
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
{_BASE_CSS}{extra_css}
  </style>
</head>
<body>
  <div class="wordmark">SHADZ</div>
  <main class="page">
    <div class="card">{inner}</div>
  </main>
</body>
</html>"""
