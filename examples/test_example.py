#!/usr/bin/env python3
"""
BGP Compliance Testing Example

This script demonstrates how to use the BGP test framework
programmatically to test BGP implementations.
"""

from bgp_test_framework.api import (
    BGPTestHarness,
    BGPTestConfig,
    BGPMessageBuilder,
    BGPParser,
    run_bgp_tests,
)


def test_remote_peer(host: str, source_as: int):
    """Run full compliance tests against a remote BGP peer."""
    print(f"Testing BGP peer at {host} (AS {source_as})...")

    config = BGPTestConfig(
        target_host=host,
        source_as=source_as,
        hold_time=180,
        timeout=10.0,
    )

    harness = BGPTestHarness(config)

    print("\n=== Running Message Header Tests ===")
    results = harness.run_category("message_header")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.test_id}: {r.test_name}")

    print("\n=== Running OPEN Message Tests ===")
    results = harness.run_category("open_message")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.test_id}: {r.test_name}")

    print("\n=== Running UPDATE Message Tests ===")
    results = harness.run_category("update_message")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.test_id}: {r.test_name}")

    report = harness.get_compliance_report(results)
    print(f"\n=== Compliance Report ===")
    print(f"  Score: {report['compliance_score']}%")
    print(f"  Grade: {report['compliance_grade']}")
    print(f"  Tests: {report['tests_passed']}/{report['total_tests']} passed")


def test_message_generation():
    """Test BGP message generation without a real peer."""
    print("\n=== Testing Message Generation ===")

    print("\n1. OPEN Message:")
    msg = BGPMessageBuilder.create_open(my_as=65001, hold_time=180)
    print(f"   Length: {len(msg)} bytes")
    parsed = BGPParser.parse_header(msg)
    print(f"   Type: {parsed['type']} (OPEN)")

    print("\n2. KEEPALIVE Message:")
    msg = BGPMessageBuilder.create_keepalive()
    print(f"   Length: {len(msg)} bytes")
    parsed = BGPParser.parse_header(msg)
    print(f"   Type: {parsed['type']} (KEEPALIVE)")

    print("\n3. NOTIFICATION Message:")
    msg = BGPMessageBuilder.create_notification(1, 1)
    print(f"   Length: {len(msg)} bytes")
    parsed = BGPParser.parse_header(msg)
    print(f"   Type: {parsed['type']} (NOTIFICATION)")

    print("\n4. ROUTE REFRESH Message:")
    msg = BGPMessageBuilder.create_route_refresh(afi=1, safi=1)
    print(f"   Length: {len(msg)} bytes")
    parsed = BGPParser.parse_header(msg)
    print(f"   Type: {parsed['type']} (ROUTE_REFRESH)")

    print("\n5. Path Attributes:")
    origin = BGPMessageBuilder.create_origin_attribute("IGP")
    print(f"   ORIGIN: type={origin.attr_type}")

    as_path = BGPMessageBuilder.create_as_path_attribute([65001, 65002])
    print(f"   AS_PATH: type={as_path.attr_type}")

    next_hop = BGPMessageBuilder.create_next_hop_attribute("192.168.1.1")
    print(f"   NEXT_HOP: type={next_hop.attr_type}")


def main():
    import sys

    if len(sys.argv) > 1:
        host = sys.argv[1]
        source_as = int(sys.argv[2]) if len(sys.argv) > 2 else 65001
        test_remote_peer(host, source_as)
    else:
        print("BGP Test Framework - Example Usage")
        print("=" * 40)
        test_message_generation()
        print("\n" + "=" * 40)
        print("\nUsage:")
        print("  python test_example.py <host> <as_number>")
        print("\nExamples:")
        print("  python test_example.py 192.168.1.1 65001")
        print("  python test_example.py                      # Message generation only")


if __name__ == "__main__":
    main()
