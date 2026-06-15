#!/usr/bin/env python3
"""Backup audit CLI entry point."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backup_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
