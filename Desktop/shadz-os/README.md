# Shadz OS Dashboard

Minimal FastAPI backend for a personal server control dashboard.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness probe |
| GET | `/status` | required | CPU, RAM, uptime |
| POST | `/run-command` | required | Run a whitelisted command |

### POST /run-command — allowed commands

| Key | Runs |
|-----|------|
| `check_disk` | `df -h` (macOS) / `df -h --output=...` (Linux) |
| `check_docker` | `docker ps --format ...` |

## Running locally

**1. Set up your API key**

```bash
cp .env.example .env
# Edit .env and set SHADZ_OS_API_KEY to a strong secret
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Start the server**

```bash
SHADZ_OS_API_KEY=your-secret-key-here uvicorn main:app --reload
```

Or with a `.env` file and [python-dotenv](https://pypi.org/project/python-dotenv/):

```bash
export $(cat .env | xargs) && uvicorn main:app --reload
```

**4. Call an endpoint**

```bash
curl http://localhost:8000/health

curl -H "X-API-Key: your-secret-key-here" http://localhost:8000/status

curl -X POST http://localhost:8000/run-command \
  -H "X-API-Key: your-secret-key-here" \
  -H "Content-Type: application/json" \
  -d '{"command": "check_disk"}'
```

## Running with Docker

```bash
docker build -t shadz-os .

docker run -p 8000:8000 \
  -e SHADZ_OS_API_KEY=your-secret-key-here \
  shadz-os
```

## Authentication

Protected endpoints require the header:

```
X-API-Key: <value of SHADZ_OS_API_KEY>
```

Missing or wrong key → `401 Unauthorized`.  
Server started without `SHADZ_OS_API_KEY` set → `500` (fail-safe, not silently open).

## Interactive docs

Available at `http://localhost:8000/docs` when the server is running.  
Click **Authorize** and enter your API key to test protected endpoints from the browser.
