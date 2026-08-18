"""Unified entrypoint: `python3 -m omada <command>`."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
