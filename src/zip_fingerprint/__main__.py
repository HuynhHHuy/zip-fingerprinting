"""Entrypoint when running `python -m zip_fingerprint`."""

import sys
from zip_fingerprint.cli import main

if __name__ == "__main__":
    sys.exit(main())

