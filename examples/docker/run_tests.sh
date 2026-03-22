#!/bin/bash
sleep 15
exec python -m bgp_test_framework.cli --target 172.16.0.2 --as-number 65000 -v
