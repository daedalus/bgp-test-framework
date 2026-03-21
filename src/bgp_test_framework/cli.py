#!/usr/bin/env python3
"""
BGPv4 Adversarial Test Framework CLI Entry Point
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from bgp_test_framework.runner import main

if __name__ == "__main__":
    main()
