"""Add src/ to sys.path so `from nvd_search.main import ...` works when
pytest is run from this tool directory without editable install."""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(_SRC))
