"""Make the sibling modules importable: <repo>/aditya (examcrypto) and <repo>/ansh (threatdetect)."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ADITYA = REPO / "aditya"
ANSH = REPO / "ansh"


def add_paths() -> None:
    for p in (ADITYA, ANSH):
        if p.is_dir() and str(p) not in sys.path:
            sys.path.insert(0, str(p))


add_paths()
