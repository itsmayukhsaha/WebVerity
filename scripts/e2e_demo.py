"""End-to-end verification: boots the FastAPI app in-process and runs one real scan."""
import json
import sys

sys.path.insert(0, ".")
import os

os.environ["DEBUG"] = "False"

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.database.connection import init_db  # noqa: E402
from backend.app.main import app  # noqa: E402

init_db()
client = TestClient(app)

resp = client.post("/api/v1/scans", json={"url": "https://example.com/"})
print("HTTP", resp.status_code)
data = resp.json()
print(json.dumps(data, indent=2, default=str)[:6000])
