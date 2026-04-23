"""Make `from src.main import ...` work whether pytest is invoked from this
tool's dir or from repo root. Matches sibling tools (nmap / dig / whatweb / ...).
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
