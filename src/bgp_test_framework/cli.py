#!/usr/bin/env python3
"""
BGPv4 Adversarial Test Framework CLI Entry Point
"""

import sys
import os


def main():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from bgp_test_framework.runner import main as runner_main

    runner_main()


if __name__ == "__main__":
    main()
