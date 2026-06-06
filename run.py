#!/usr/bin/env python3
"""Qulay ishga tushiruvchi:  python run.py scan ./samples/vulnerable-app

(`python -m secscan ...` ham ishlaydi.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secscan.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
