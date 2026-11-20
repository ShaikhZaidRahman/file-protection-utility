#!/usr/bin/env python3
"""Run fileprotect straight from a source checkout (no installation needed).

python filecrypt.py encrypt secret.txt
python filecrypt.py decrypt secret.txt.enc
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fileprotect.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
