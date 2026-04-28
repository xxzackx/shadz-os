import os
import time
import platform
import subprocess
import psutil
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

app = FastAPI(title="Shadz OS Dashboard", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*", "X-API-Key"],
)

BOOT_TIME = psutil.boot_time()

# ---------------------------------------------------------------------------
# API key auth — reads SHADZ_OS_API_KEY from environment at startup
# ---------------------------------------------------------------------------

_API_KEY = os.environ.get("SHADZ_OS_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(_api_key_header)) -> str:
    if not _API_KEY:
        raise HTTPException(status_code=500, detail="Server has no API key configured")
    if not key or key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")
    return key


# ---------------------------------------------------------------------------
# Safe command registry — only these are ever executed
# ---------------------------------------------------------------------------

_DF_CMD = (
    ["df", "-h"]
    if platform.system() == "Darwin"
    else ["df", "-h", "--output=source,size,used,avail,pcent,target"]
)

SAFE_COMMANDS: dict[str, list[str]] = {
    "check_docker": ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
    "check_disk":   _DF_CMD,
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CommandRequest(BaseModel):
    command: str


class CommandResult(BaseModel):
    command: str
    output: str
    exit_code: int


class ServerStatus(BaseModel):
    cpu_percent: float
    ram_percent: float
    ram_used_mb: float
    ram_total_mb: float
    uptime_seconds: float


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/status", response_model=ServerStatus)
def get_status(_key=Depends(require_api_key)):
    mem = psutil.virtual_memory()
    return ServerStatus(
        cpu_percent=psutil.cpu_percent(interval=0.5),
        ram_percent=mem.percent,
        ram_used_mb=round(mem.used / 1024 / 1024, 1),
        ram_total_mb=round(mem.total / 1024 / 1024, 1),
        uptime_seconds=round(time.time() - BOOT_TIME, 1),
    )


@app.post("/run-command", response_model=CommandResult)
def run_command(req: CommandRequest, _key=Depends(require_api_key)):
    if req.command not in SAFE_COMMANDS:
        allowed = list(SAFE_COMMANDS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command. Allowed: {allowed}",
        )

    argv = SAFE_COMMANDS[req.command]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            # Never pass shell=True — argv is a fixed list, not user input
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Binary not found: {argv[0]}")

    output = result.stdout or result.stderr
    return CommandResult(
        command=req.command,
        output=output.strip(),
        exit_code=result.returncode,
    )


@app.get("/health")
def health():
    return {"status": "ok"}
