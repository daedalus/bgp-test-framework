# BGP Adversarial Test Framework

A comprehensive adversarial testing framework for BGP v1 to v4 implementations based on RFC specifications.

## Intended Use

This tool is designed as an RFC compliance testing utility for researchers and network engineers evaluating BGP implementation conformance. While it includes tests for security-related protocol behaviors, it is primarily intended to assist in compliance verification and protocol analysis rather than security auditing or penetration testing activities.

**Caveat**: This is an RFC compliance testing tool. It may assist security researchers in evaluating BGP implementations, but security assessment is not its primary purpose, and it is not intended for use in penetration testing activities.

## Overview

This framework provides automated testing capabilities to identify vulnerabilities and protocol violations in BGPv4 implementations. It includes tests for:

- Message header validation (RFC 4271 Section 4.1, 6.1)
- OPEN message handling (RFC 4271 Section 4.2, 6.2)
- UPDATE message processing (RFC 4271 Section 4.3, 6.3)
- Path attribute validation (RFC 4271 Section 5)
- Finite State Machine behavior (RFC 4271 Section 8)
- Timing and Keepalive behavior (RFC 4271 Section 4.4, 10)
- Route aggregation (RFC 4271 Section 9.2.2)
- Decision process (RFC 4271 Section 9.1)
- Security considerations (RFC 4271 Section 6, RFC 4272)

## Features

- **Comprehensive Test Coverage**: Tests based on RFC 4271 and RFC 4272 requirements
- **Security Vulnerability Testing**: Tests for BGP security attacks from RFC 4272
- **Configurable Testing**: YAML configuration for complex test scenarios
- **Multiple Output Formats**: JSON and YAML report generation
- **Detailed Reporting**: Pass/fail status with expected vs actual behavior
- **Selective Test Execution**: Run specific tests or categories

## Installation

```bash
pip install -e .
```

## Quick Start

### Basic Usage

```bash
bgp-test --target 192.168.1.1 --as-number 65001
```

### With Configuration File

```bash
bgp-test --config config.yaml
```

### Run Specific Tests

```bash
bgp-test --target 192.168.1.1 --test-ids MH-001 MH-002 MH-003
```

### Run Test Categories

```bash
bgp-test --target 192.168.1.1 --categories message_header open_message
```

## Programmatic API

The framework provides a Python API for programmatic testing:

```python
from bgp_test_framework.api import run_bgp_tests, BGPTestHarness, BGPTestConfig

# Quick start - run all tests
result = run_bgp_tests("192.168.1.1", 65001)
print(f"Compliance Score: {result['compliance_score']}%")
print(f"Grade: {result['compliance_grade']}")

# Run specific categories
result = run_bgp_tests(
    "192.168.1.1",
    65001,
    categories=["message_header", "open_message"]
)

# Use the test harness for more control
config = BGPTestConfig(
    target_host="192.168.1.1",
    source_as=65001,
    hold_time=180
)
harness = BGPTestHarness(config)
tests = harness.get_all_tests("message_header")
results = harness.run_category("message_header")
report = harness.get_compliance_report(results)
```

### Message Builder API

Build BGP messages programmatically:

```python
from bgp_test_framework.api import BGPMessageBuilder

# Build messages
open_msg = BGPMessageBuilder.create_open(my_as=65001, hold_time=180)
keepalive = BGPMessageBuilder.create_keepalive()
notification = BGPMessageBuilder.create_notification(1, 1)
route_refresh = BGPMessageBuilder.create_route_refresh(afi=1, safi=1)

# Build path attributes
origin = BGPMessageBuilder.create_origin_attribute("IGP")
as_path = BGPMessageBuilder.create_as_path_attribute([65001, 65002])
next_hop = BGPMessageBuilder.create_next_hop_attribute("192.168.1.1")

# Build multiprotocol attributes
mp_reach = BGPMessageBuilder.create_mp_reach(2, 1, b"\xc0\xa8\x01\x01", nlri)
originator_id = BGPMessageBuilder.create_originator_id(0x0A000001)
cluster_list = BGPMessageBuilder.create_cluster_list([1, 2, 3])
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target BGP peer IP address (required) |
| `--port`, `-p` | BGP port (default: 179) |
| `--as-number`, `-a` | Source AS number (default: 65001) |
| `--source-ip` | Source IP address |
| `--bgp-id` | BGP Identifier |
| `--hold-time` | Hold time in seconds (default: 180) |
| `--timeout` | Connection timeout (default: 5.0) |
| `--categories` | Test categories to run |
| `--test-ids` | Specific test IDs to run |
| `--config`, `-c` | YAML configuration file |
| `--output`, `-o` | Output file for results |
| `--format` | Output format (json/yaml) |
| `--verbose`, `-v` | Verbose output |
| `--debug`, `-d` | Debug output |

## Test Categories

### message_header
Tests for BGP message header validation per RFC 4271 Section 4.1 and 6.1:
- MH-001: Invalid Marker
- MH-003: Message Length Too Short
- MH-004: Message Length Too Large
- MH-006: Invalid Message Type
- MH-009: OPEN Message Length Too Short
- MH-010: UPDATE Message Length Too Short
- MH-011: KEEPALIVE Message Wrong Length
- MH-012: NOTIFICATION Message Length Too Short

### graceful_restart
Tests for Graceful Restart per RFC 4724:
- GR-001: Graceful Restart Capability
- GR-002: Graceful Restart Timer
- GR-003: End-of-RIB Marker
- GR-004: Graceful Restart State
- GR-005: Graceful Restart AFI/SAFI

### enhanced_route_refresh
Tests for Enhanced Route Refresh per RFC 7313:
- ERR-001: Enhanced Route Refresh Capability
- ERR-002: Outbound Route Refresh
- ERR-003: Inbound Route Refresh
- ERR-004: Route Refresh with ORF Prefix
- ERR-005: Route Refresh AFI/SAFI

### extended_messages
Tests for Extended Message support per RFC 7606:
- EXT-001: Extended Message Capability
- EXT-002: Extended Message Size
- EXT-003: Message Length Overflow
- EXT-004: Extended Message Type
- EXT-005: Extended Keepalive

### orf_filtering
Tests for Outbound Route Filtering per RFC 5291:
- ORF-001: ORF Capability
- ORF-002: ORF Send Receive
- ORF-003: ORF Prefix Filter
- ORF-004: ORF Route Refresh
- ORF-005: ORF Multiple Entries

### dynamic_capability
Tests for Dynamic Capability per RFC 6724:
- DC-001: Dynamic Capability Advertisement
- DC-002: Capability Refresh
- DC-003: Unknown Capability
- DC-004: Capability Length Error
- DC-005: Multiple Capabilities

### open_message
Tests for OPEN message handling per RFC 4271 Section 4.2 and 6.2:
- OP-001: Unsupported BGP Version
- OP-005: Hold Time One (MUST reject)
- OP-008: Invalid BGP Identifier - All Zeros
- OP-011: Unknown Optional Parameter

### update_message
Tests for UPDATE message processing per RFC 4271 Section 4.3 and 6.3:
- UP-001: Missing ORIGIN Attribute
- UP-002: Missing AS_PATH Attribute
- UP-003: Missing NEXT_HOP Attribute
- UP-004: Invalid ORIGIN Value
- UP-005: Malformed AS_PATH
- UP-011: Attribute Length Mismatch
- UP-012: Duplicate Attribute

### attribute
Tests for path attribute validation per RFC 4271 Section 5:
- ATTR-001: AS_PATH Loop Detection
- ATTR-005: LOCAL_PREF on EBGP
- ATTR-007: AGGREGATOR Invalid Length

### fsm
Tests for Finite State Machine behavior per RFC 4271 Section 8:
- FSM-001: UPDATE in Idle State
- FSM-002: UPDATE in Connect State
- FSM-005: KEEPALIVE in Idle State

### timing
Tests for timing behavior per RFC 4271 Section 10:
- TIM-001: Hold Timer Expiry
- TIM-002: KEEPALIVE Rate Limit
- TIM-003: Zero Hold Time No KEEPALIVE

### security
Tests for security considerations per RFC 4271 Section 6:
- SEC-001: Connection Collision Detection
- SEC-002: BGP Identifier Collision
- SEC-006: TCP RST Injection
- SEC-008: AS_PATH Shortening Attack
- SEC-009: False Route Origination
- SEC-010: NEXT_HOP Manipulation
- SEC-011: ORIGIN Attribute Manipulation
- SEC-012: LOCAL_PREF Manipulation
- SEC-014: Route Withdrawal Replay
- SEC-016: ATOMIC_AGGREGATE Manipulation
- SEC-019: Invalid AS_PATH Leftmost AS

### route_aggregation
Tests for route aggregation per RFC 4271 Section 9.2.2:
- AGG-001: AS_SET Sorting
- AGG-002: Aggregation Without AS_SET
- AGG-005: ATOMIC_AGGREGATE Restriction
- AGG-006: Complex AS_PATH Aggregation

### decision_process
Tests for BGP decision process per RFC 4271 Section 9.1:
- DEC-001: Route Selection - Highest LOCAL_PREF
- DEC-002: Route Selection - Shortest AS_PATH
- DEC-003: Route Selection - ORIGIN Priority
- DEC-008: Route Resolvability
- DEC-010: AS_PATH with Own AS Loop

### confederation
Tests for AS confederations per RFC 3065:
- CONFED-001: AS_CONFED_SEQUENCE Path Attribute
- CONFED-002: AS_CONFED_SET Path Attribute
- CONFED-003: Confederation Identifier Loop Detection
- CONFED-004: Member-AS Loop Detection

### keepalive_message
Tests for KEEPALIVE message handling per RFC 4271 Section 4.4:
- KA-001: KEEPALIVE in Wrong State
- KA-002: KEEPALIVE Wrong Length
- KA-004: KEEPALIVE in Connect State
- KA-005: KEEPALIVE in OpenSent State

### notification_message
Tests for NOTIFICATION message handling per RFC 4271 Section 4.5 and 6.4:
- NOT-001: NOTIFICATION in Idle State
- NOT-002: NOTIFICATION Message Too Short
- NOT-005: Cease Notification

### version_negotiation
Tests for BGP version negotiation per RFC 4271 Section 7:
- VN-001: BGP Version 1
- VN-002: BGP Version 2
- VN-003: BGP Version 3
- VN-004: BGP Version 0
- VN-005: BGP Version 5 (Future)

### connection_collision
Tests for BGP connection collision detection per RFC 4271 Section 6.8:
- COL-001: Simultaneous Connection Open
- COL-002: Same BGP Identifier
- COL-003: Higher BGP Identifier Wins

## Configuration File

Example YAML configuration:

```yaml
# Target configuration
target: "192.168.1.1"
port: 179
source_as: 65001
source_ip: "10.0.0.1"
bgp_id: "10.0.0.1"
hold_time: 180
timeout: 5.0

# Test selection
test_categories:
  - message_header
  - open_message
  - update_message

test_ids:
  - MH-001
  - OP-001

# Test behavior
delay_between_tests: 0.5
retry_count: 1

# Output
output: "results.json"
format: "json"
verbose: true
debug: false
```

## Output Format

### JSON Output

```json
{
  "summary": {
    "total": 50,
    "passed": 45,
    "failed": 5,
    "pass_rate": "90.0%",
    "target": "192.168.1.1:179",
    "source_as": 65001,
    "by_category": {
      "message_header": {"total": 14, "passed": 14, "failed": 0},
      "open_message": {"total": 15, "passed": 13, "failed": 2}
    }
  },
  "results": [
    {
      "test_id": "MH-001",
      "test_name": "Invalid Marker",
      "category": "message_header",
      "passed": true,
      "expected_behavior": "Send OPEN with invalid marker",
      "actual_behavior": "NOTIFICATION received: code=1, subcode=1"
    }
  ]
}
```

## Testing Considerations

### Legal and Ethical Use

This framework is intended for:
- Security research and vulnerability assessment
- Protocol compliance testing
- Network device validation
- Educational purposes

**WARNING**: Only test systems you own or have explicit permission to test. Unauthorized testing may be illegal.

### Test Prerequisites

1. Network connectivity to target BGP peer
2. Target BGP speaker must be reachable on TCP port 179
3. No firewall blocking the connection

## Development

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Functional tests
pytest tests/functional/

# All tests
pytest tests/
```

### Project Structure

```
bgp_test_framework/
├── src/bgp_test_framework/
│   ├── __init__.py
│   ├── constants.py       # RFC 4271/4272 constants
│   ├── messages.py        # BGP message parsing/building
│   ├── tests.py           # Test case definitions (210+ tests)
│   ├── runner.py          # Test execution engine
│   ├── api.py             # Programmatic API
│   └── cli.py             # CLI entry point
├── tests/
│   ├── unit/              # Unit tests
│   └── functional/         # Functional tests
├── RFCs/                  # RFC specification documents
│   ├── rfc1105.txt        # RFC 1105 (BGP v1, obsolete)
│   ├── rfc1163.txt        # RFC 1163 (BGP-2, obsolete)
│   ├── rfc1267.txt        # RFC 1267 (BGP-3, obsolete)
│   ├── rfc1771.txt        # RFC 1771 (BGP-4, obsolete)
│   ├── rfc2918.txt        # RFC 2918 (Route Refresh)
│   ├── rfc3065.txt        # RFC 3065 (AS Confederations)
│   ├── rfc4271.txt        # RFC 4271 (BGP-4)
│   └── rfc4272.txt        # RFC 4272 (BGP Security)
├── config.yaml            # Example configuration
├── pyproject.toml        # Project configuration
└── README.md
```

## References

- [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://www.rfc-editor.org/rfc/rfc4271)
- [RFC 4272 - BGP Security Vulnerabilities Analysis](https://www.rfc-editor.org/rfc/rfc4272)
- [RFC 2918 - Route Refresh Capability for BGP-4](https://www.rfc-editor.org/rfc/rfc2918)
- [RFC 3065 - Autonomous System Confederations for BGP](https://www.rfc-editor.org/rfc/rfc3065)
- [RFC 4724 - Graceful Restart Mechanism for BGP](https://www.rfc-editor.org/rfc/rfc4724)
- [RFC 7313 - Enhanced Route Refresh Capability for BGP-4](https://www.rfc-editor.org/rfc/rfc7313)
- [RFC 4760 - Multiprotocol Extensions for BGP-4](https://www.rfc-editor.org/rfc/rfc4760)
- [RFC 4456 - Route Reflection](https://www.rfc-editor.org/rfc/rfc4456)
- [RFC 4893 - BGP Support for Four-Octet AS Number Space](https://www.rfc-editor.org/rfc/rfc4893)
- [RFC 1105 - BGP (obsolete)](https://www.rfc-editor.org/rfc/rfc1105)
- [RFC 1163 - BGP-2 (obsolete)](https://www.rfc-editor.org/rfc/rfc1163)
- [RFC 1267 - BGP-3 (obsolete)](https://www.rfc-editor.org/rfc/rfc1267)
- [RFC 1771 - BGP-4 (obsolete)](https://www.rfc-editor.org/rfc/rfc1771)

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome. Please submit issues and pull requests on the project repository.
