"""Make `from src.main import ...` work from repo root. Same pattern as
sibling tools (nmap/nuclei/feroxbuster/http_fetch)."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
