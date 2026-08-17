"""Safety Engine v1 Phase S2 — public NFC-originated entry point.

Render-only: GET /safety/c/{secure_token} resolves an active SafetyUser and
shows a minimal identity shell. Performs no Safety runtime writes. Unknown
token and inactive-user token return an identical 404 so token validity is
never distinguishable from the outside.
"""
import html

import models
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

_NOT_FOUND_DETAIL = "Not found"


def _safety_entry_html(display_name: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ Safety</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#c9a84c;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif;
         flex-direction:column;gap:1rem;padding:2rem;text-align:center}}
    p.eyebrow{{font-size:.7rem;letter-spacing:.25em;text-transform:uppercase;color:#4a4540}}
    h1{{font-size:1.4rem;letter-spacing:.05em;color:#f2e6c9}}
  </style>
</head>
<body>
  <p class="eyebrow">SHADZ Safety</p>
  <h1>{html.escape(display_name)}</h1>
</body>
</html>"""


def serve_safety_entry(secure_token: str, db: Session) -> HTMLResponse:
    user = (
        db.query(models.SafetyUser)
        .filter(models.SafetyUser.secure_token == secure_token)
        .first()
    )
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_DETAIL)
    return HTMLResponse(content=_safety_entry_html(user.display_name))
