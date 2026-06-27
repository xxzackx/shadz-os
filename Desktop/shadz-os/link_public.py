import models
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# Public link HTML templates
# ---------------------------------------------------------------------------

def _expired_page_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#000;color:#4a4540;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif;
         flex-direction:column;gap:1.5rem;padding:2rem;text-align:center}
    p{font-size:.75rem;letter-spacing:.2em;text-transform:uppercase;line-height:1.8}
    a{display:inline-block;margin-top:.5rem;padding:.55rem 1.4rem;
      border:1px solid #2a2520;border-radius:5px;
      font-size:.65rem;letter-spacing:.15em;text-transform:uppercase;
      color:#4a4540;text-decoration:none;transition:border-color .15s,color .15s}
    a:hover{border-color:#7a5f28;color:#c9a84c}
  </style>
</head>
<body>
  <p>SHADZ EXPERIENCE HAS EXPIRED.<br>CONTACT US TO REACTIVATE.</p>
  <a href="https://t.me/xshadzx" target="_blank" rel="noopener noreferrer">Contact</a>
</body>
</html>"""


def _media_page_html(asset: models.MediaAsset) -> str:
    """Minimal dark media page rendered for GET /{media-slug}."""
    url = asset.public_url
    mt  = asset.media_type
    if mt == "video":
        media_block = (
            f'<video src="{url}" controls autoplay playsinline '
            f'style="max-width:100%;max-height:90vh;border-radius:6px"></video>'
        )
    elif mt in ("image", "gif"):
        media_block = (
            f'<img src="{url}" alt="media" '
            f'style="max-width:100%;max-height:90vh;object-fit:contain;border-radius:6px" />'
        )
    elif mt == "audio":
        media_block = (
            f'<div style="text-align:center;padding:2rem">'
            f'<p style="color:#7a5f28;font-size:.75rem;letter-spacing:.15em;'
            f'text-transform:uppercase;margin-bottom:1.5rem">Audio</p>'
            f'<audio src="{url}" controls autoplay '
            f'style="width:100%;max-width:480px"></audio></div>'
        )
    else:
        media_block = f'<a href="{url}" style="color:#c9a84c">Open Media</a>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#d4d0c8;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}}
    .wordmark{{position:fixed;top:1rem;left:50%;transform:translateX(-50%);
               font-family:system-ui,sans-serif;font-size:.65rem;
               letter-spacing:.25em;text-transform:uppercase;color:#2a2520}}
  </style>
</head>
<body>
  <div class="wordmark">SHADZ</div>
  {media_block}
</body>
</html>"""


def _media_not_ready_html(slug: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#4a4540;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif}}
    p{{font-size:.75rem;letter-spacing:.2em;text-transform:uppercase}}
  </style>
</head>
<body><p>Media not ready yet</p></body>
</html>"""


# ---------------------------------------------------------------------------
# Public link handlers
# ---------------------------------------------------------------------------

def expired_page_response() -> HTMLResponse:
    """Return the 410 HTMLResponse for an archived slug."""
    return HTMLResponse(
        content=_expired_page_html(),
        status_code=410,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma":        "no-cache",
            "Expires":       "0",
        },
    )


def serve_public_media(slug: str, db: Session) -> HTMLResponse:
    """Handle the media content_type branch of the public slug route."""
    sm = (db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == slug,
                    models.SlugMedia.is_active == True)
            .first())
    if not sm:
        return HTMLResponse(content=_media_not_ready_html(slug))
    asset = db.query(models.MediaAsset).filter(
        models.MediaAsset.id == sm.media_asset_id
    ).first()
    if not asset or asset.is_deleted:
        return HTMLResponse(content=_media_not_ready_html(slug))
    return HTMLResponse(content=_media_page_html(asset))
