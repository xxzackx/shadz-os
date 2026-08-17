"""Safety Engine v1 Phase S3 — check-in UI + mandatory GPS + SOS UI.

Render-only: GET /safety/c/{secure_token} resolves an active SafetyUser and
shows the v1 check-in interface (I'M SAFE / SOS actions gated on browser
geolocation). Performs no Safety runtime writes -- I'M SAFE and SOS are
client-side gated UX only in this phase; the server-side check-in/SOS
execution (DB writes, alerts, notifications) belongs to Phase S4. Unknown
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
         flex-direction:column;gap:1.25rem;padding:2rem 1.25rem;text-align:center}}
    p.eyebrow{{font-size:.7rem;letter-spacing:.25em;text-transform:uppercase;color:#4a4540}}
    h1{{font-size:1.4rem;letter-spacing:.05em;color:#f2e6c9}}
    main{{width:100%;max-width:420px;display:flex;flex-direction:column;gap:1.25rem}}

    #location-status{{border:1px solid #33301f;border-radius:.5rem;padding:.75rem 1rem;
         font-size:.85rem;line-height:1.4;color:#a89a6b}}
    #location-status[data-state="requesting"]{{color:#c9a84c}}
    #location-status[data-state="acquired"]{{color:#7fd18a;border-color:#2c4a2f}}
    #location-status[data-state="denied"],
    #location-status[data-state="unavailable"],
    #location-status[data-state="timeout"]{{color:#e07a6b;border-color:#4a2c2c}}

    button{{font:inherit;letter-spacing:.05em;border-radius:.6rem;padding:1rem 1.25rem;
         cursor:pointer;border:1px solid transparent;transition:opacity .15s ease}}
    button:disabled{{opacity:.4;cursor:not-allowed}}

    #safe-btn{{background:#c9a84c;color:#000;font-size:1.05rem;font-weight:600}}
    #sos-btn{{background:#3a0d0d;color:#ff5c4d;border-color:#7a1f1f;
         font-size:1.05rem;font-weight:700;letter-spacing:.1em}}
    #sos-not-operational{{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;
         color:#ff5c4d;margin-top:-.75rem}}

    #action-feedback{{font-size:.8rem;color:#a89a6b;min-height:1.2em}}
  </style>
</head>
<body>
  <p class="eyebrow">SHADZ Safety</p>
  <h1 id="identity-name">{html.escape(display_name)}</h1>
  <main>
    <div id="location-status" data-state="requesting" role="status" aria-live="polite">
      Requesting your location&hellip;
    </div>

    <button id="safe-btn" type="button" disabled aria-disabled="true">I&#39;M SAFE</button>
    <button id="sos-btn" type="button" disabled aria-disabled="true">SOS&#128680;</button>
    <p id="sos-not-operational">Not yet operational &mdash; no alert will be sent</p>

    <p id="action-feedback" role="status" aria-live="polite"></p>
  </main>

  <script>
    (function () {{
      var statusEl = document.getElementById('location-status');
      var safeBtn = document.getElementById('safe-btn');
      var sosBtn = document.getElementById('sos-btn');
      var feedbackEl = document.getElementById('action-feedback');
      var lastPosition = null;

      function setState(state, message) {{
        statusEl.setAttribute('data-state', state);
        statusEl.textContent = message;
        var acquired = state === 'acquired';
        safeBtn.disabled = !acquired;
        safeBtn.setAttribute('aria-disabled', String(!acquired));
        sosBtn.disabled = !acquired;
        sosBtn.setAttribute('aria-disabled', String(!acquired));
      }}

      function requestLocation() {{
        if (!('geolocation' in navigator)) {{
          setState('unavailable', 'Location is unavailable on this device/browser. I\\'M SAFE and SOS require your location.');
          return;
        }}
        setState('requesting', 'Requesting your location\\u2026');
        navigator.geolocation.getCurrentPosition(
          function (position) {{
            lastPosition = position;
            setState('acquired', 'Location acquired. You can now check in.');
          }},
          function (error) {{
            if (error.code === error.PERMISSION_DENIED) {{
              setState('denied', 'Location permission denied. Enable location access and retry to check in.');
            }} else if (error.code === error.POSITION_UNAVAILABLE) {{
              setState('unavailable', 'Location unavailable right now. Retry to check in.');
            }} else if (error.code === error.TIMEOUT) {{
              setState('timeout', 'Location request timed out. Retry to check in.');
            }} else {{
              setState('unavailable', 'Could not acquire location. Retry to check in.');
            }}
          }},
          {{ enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }}
        );
      }}

      statusEl.addEventListener('click', function () {{
        if (statusEl.getAttribute('data-state') !== 'acquired') {{
          requestLocation();
        }}
      }});

      safeBtn.addEventListener('click', function () {{
        if (!lastPosition) return;
        feedbackEl.textContent = 'Check-in ready (location confirmed). Submission is not yet enabled.';
      }});

      sosBtn.addEventListener('click', function () {{
        if (!lastPosition) return;
        feedbackEl.textContent = 'SOS is not yet operational in this version. No emergency alert was sent.';
      }});

      requestLocation();
    }})();
  </script>
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
