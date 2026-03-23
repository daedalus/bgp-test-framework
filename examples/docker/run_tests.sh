#!/bin/bash
set -x
#sleep 5
exec python -m bgp_test_framework.cli --config /app/config.yaml --target 172.16.0.2 --as-number 65000 --timeout 5 --categories all -v
