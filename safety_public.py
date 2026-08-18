"""Safety Engine v1 Phase S4 — secure check-in / SOS submission.

GET /safety/c/{secure_token} resolves an active SafetyUser and shows the v1
check-in interface (I'M SAFE / SOS actions gated on browser geolocation).
POST /safety/c/{secure_token}/check-in and POST /safety/c/{secure_token}/sos
are the secure server-side submission endpoints for those two actions: they
resolve the SafetyUser from the secure token (never a client-supplied user
id), validate the submitted GPS payload, and persist a SafetyCheckIn /
SafetyEmergency row with a server-generated timestamp. Unknown token and
inactive-user token return an identical 404 across all three routes so token
validity is never distinguishable from the outside.
"""
import html
import math
from datetime import timezone

import models
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator
from safety_deadline import resolve_checkin
from safety_notify import claim_late_checkin_alert
from sqlalchemy.orm import Session

_NOT_FOUND_DETAIL = "Not found"

# Phase S4 public web check-in source, distinct from any future admin/manual
# or Telegram-originated source values.
_CHECKIN_SOURCE_PUBLIC_WEB = "public_web"


class SafetyGPSPayload(BaseModel):
    """Body for the S4 check-in/SOS POST endpoints.

    Intentionally carries only GPS data -- no user id or timestamp field
    exists, so there is nothing client-supplied to trust for identity or
    time; both are always derived server-side (secure_token -> user,
    datetime.now(utc) via the model column default).
    """
    latitude: float
    longitude: float
    accuracy: float | None = None

    @field_validator("latitude")
    @classmethod
    def _validate_latitude(cls, value: float) -> float:
        if not math.isfinite(value) or not (-90.0 <= value <= 90.0):
            raise ValueError("latitude must be a finite number in [-90, 90]")
        return value

    @field_validator("longitude")
    @classmethod
    def _validate_longitude(cls, value: float) -> float:
        if not math.isfinite(value) or not (-180.0 <= value <= 180.0):
            raise ValueError("longitude must be a finite number in [-180, 180]")
        return value

    @field_validator("accuracy")
    @classmethod
    def _validate_accuracy(cls, value: float | None) -> float | None:
        if value is None:
            return value
        if not math.isfinite(value) or value < 0:
            raise ValueError("accuracy must be a non-negative number")
        return value


class SafetyCheckInResponse(BaseModel):
    status: str


class SafetySOSResponse(BaseModel):
    status: str


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

    <p id="action-feedback" role="status" aria-live="polite"></p>
  </main>

  <script>
    (function () {{
      var statusEl = document.getElementById('location-status');
      var safeBtn = document.getElementById('safe-btn');
      var sosBtn = document.getElementById('sos-btn');
      var feedbackEl = document.getElementById('action-feedback');
      var lastPosition = null;
      var submitting = false;
      var safeLocked = false;
      var sosLocked = false;
      var checkinUrl = window.location.pathname + '/check-in';
      var sosUrl = window.location.pathname + '/sos';

      function setState(state, message) {{
        statusEl.setAttribute('data-state', state);
        statusEl.textContent = message;
        var acquired = state === 'acquired';
        var safeEnabled = acquired && !submitting && !safeLocked;
        var sosEnabled = acquired && !submitting && !sosLocked;
        safeBtn.disabled = !safeEnabled;
        safeBtn.setAttribute('aria-disabled', String(!safeEnabled));
        sosBtn.disabled = !sosEnabled;
        sosBtn.setAttribute('aria-disabled', String(!sosEnabled));
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

      function submitAction(url, pendingMessage, successMessage, errorMessage, onSuccess) {{
        if (!lastPosition || submitting) return;
        submitting = true;
        setState(statusEl.getAttribute('data-state'), statusEl.textContent);
        feedbackEl.textContent = pendingMessage;

        var body = {{
          latitude: lastPosition.coords.latitude,
          longitude: lastPosition.coords.longitude
        }};
        if (lastPosition.coords.accuracy !== null && lastPosition.coords.accuracy !== undefined) {{
          body.accuracy = lastPosition.coords.accuracy;
        }}

        fetch(url, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(body)
        }}).then(function (response) {{
          if (!response.ok) {{ throw new Error('request failed'); }}
          feedbackEl.textContent = successMessage;
          onSuccess();
        }}).catch(function () {{
          feedbackEl.textContent = errorMessage;
        }}).then(function () {{
          submitting = false;
          setState(statusEl.getAttribute('data-state'), statusEl.textContent);
        }});
      }}

      safeBtn.addEventListener('click', function () {{
        submitAction(
          checkinUrl,
          'Checking in…',
          'Checked in. Thank you.',
          'Check-in failed. Please try again.',
          function () {{ safeLocked = true; }}
        );
      }});

      sosBtn.addEventListener('click', function () {{
        submitAction(
          sosUrl,
          'Sending SOS…',
          'SOS received.',
          'SOS failed to send. Please try again or seek help directly.',
          function () {{ sosLocked = true; }}
        );
      }});

      requestLocation();
    }})();
  </script>
</body>
</html>"""


def _resolve_active_safety_user(secure_token: str, db: Session) -> models.SafetyUser:
    """Resolve the active SafetyUser for a secure_token, or 404.

    Shared by the GET entry route and the S4 POST submission routes so
    unknown-token and inactive-user cases stay indistinguishable everywhere
    the secure_token is accepted.
    """
    user = (
        db.query(models.SafetyUser)
        .filter(models.SafetyUser.secure_token == secure_token)
        .first()
    )
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_DETAIL)
    return user


def serve_safety_entry(secure_token: str, db: Session) -> HTMLResponse:
    user = _resolve_active_safety_user(secure_token, db)
    return HTMLResponse(content=_safety_entry_html(user.display_name))


def submit_check_in(
    secure_token: str, payload: SafetyGPSPayload, db: Session
) -> SafetyCheckInResponse:
    """Phase S4 — secure server-side I'M SAFE submission.

    checked_in_at is never taken from the client -- SafetyCheckIn.checked_in_at
    defaults to datetime.now(utc) at insert time, so simply omitting it here
    guarantees a server-authoritative timestamp.

    Phase S5: the check-in insert and its SafetyDailyState resolution commit
    together as a single transaction -- resolve_checkin() only flushes, so
    if anything here raises before the final commit, neither the check-in
    row nor a partial daily-state change is persisted.

    Phase S6.1: if this check-in lands at/after its safety day's deadline
    and that day isn't (and doesn't become) SAFE, it's a late check-in --
    claim_late_checkin_alert records that fact (one-shot per user/day) for
    the async notify loop to deliver to Admin. claim_late_checkin_alert also
    only flushes, never commits, so this claim joins the same atomic
    transaction as the check-in insert and the daily-state resolution above
    -- if anything raises before the single db.commit() below, the check-in,
    any daily-state change, and the late-checkin claim all roll back
    together; none of them can be left half-persisted. This never changes
    S5's locked daily-state rule (MISSED stays terminal, a late check-in
    never rewrites it back to SAFE) -- it is purely a notification-routing
    record, read only by safety_notify.collect_due_late_checkin_alerts.
    """
    user = _resolve_active_safety_user(secure_token, db)
    check_in = models.SafetyCheckIn(
        user_id=user.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy_m=payload.accuracy,
        source=_CHECKIN_SOURCE_PUBLIC_WEB,
    )
    db.add(check_in)
    db.flush()
    daily_state = resolve_checkin(db, user, check_in)

    checked_in_at = check_in.checked_in_at
    if checked_in_at.tzinfo is None:
        checked_in_at = checked_in_at.replace(tzinfo=timezone.utc)
    deadline_utc = daily_state.deadline_utc
    if deadline_utc.tzinfo is None:
        deadline_utc = deadline_utc.replace(tzinfo=timezone.utc)
    if daily_state.status != "safe" and checked_in_at >= deadline_utc:
        claim_late_checkin_alert(db, user.id, daily_state.safety_date, check_in.id)

    db.commit()
    return SafetyCheckInResponse(status="ok")


def submit_sos(secure_token: str, payload: SafetyGPSPayload, db: Session) -> SafetySOSResponse:
    """Phase S4 — secure server-side SOS submission.

    Persists the SafetyEmergency row and returns; no notification/escalation
    call is made here (out of S4 scope), so a future notification failure can
    never cause the SOS itself to be lost -- the row is already committed.
    """
    user = _resolve_active_safety_user(secure_token, db)
    emergency = models.SafetyEmergency(
        user_id=user.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy_m=payload.accuracy,
        status="open",
    )
    db.add(emergency)
    db.commit()
    return SafetySOSResponse(status="received")
