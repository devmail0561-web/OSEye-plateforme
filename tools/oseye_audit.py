#!/usr/bin/env python3
"""Compatibility shim — delegates to the modular audit package."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools.audit.cli import main

sys.exit(main())
