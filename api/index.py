from __future__ import annotations

import sys
import os

# Make sure backend modules (analyzer, web_ui) are importable from the api/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from main import app  # noqa: F401 — Vercel looks for `app` in this file
