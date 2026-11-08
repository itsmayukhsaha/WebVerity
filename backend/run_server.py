"""Production server launcher.

Starts uvicorn from /src so the `backend.app.*` package imports resolve,
and defaults the SQLite database to a writable data directory in
containerized environments (WEBVERITY_DATA_DIR, default /data).
"""

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("WEBVERITY_DATA_DIR", "/data"))
if not DATA_DIR.exists():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        DATA_DIR = Path.cwd()  # fall back to the working directory

if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = f"sqlite:///{DATA_DIR / 'webverity.db'}"

os.chdir(Path(__file__).resolve().parent.parent)  # repo root
import sys  # noqa: E402

if str(Path.cwd()) not in sys.path:
    sys.path.insert(0, str(Path.cwd()))

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        timeout_keep_alive=30,
        access_log=True,
    )
