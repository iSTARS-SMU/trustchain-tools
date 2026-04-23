"""Make `from src.main import ...` work whether pytest is invoked from this
tool's dir or from the repo root. Adds this tool dir to ``sys.path`` so the
top-level ``src`` package resolves to THIS tool's source — not a sibling
tool's ``src/`` collected earlier in the same session.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
