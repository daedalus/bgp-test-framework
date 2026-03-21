# BGPv4 Adversarial Test Framework

A comprehensive adversarial testing framework for BGPv4 implementations based on RFC 4271 and RFC 4272 specifications.

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
│   ├── tests.py           # Test case definitions (100+ tests)
│   ├── runner.py          # Test execution engine
│   └── cli.py             # CLI entry point
├── tests/
│   ├── unit/              # Unit tests
│   └── functional/        # Functional tests
├── config.yaml            # Example configuration
├── rfc4271.txt            # RFC 4271 source
├── rfc4272.txt            # RFC 4272 source
├── pyproject.toml         # Project configuration
└── README.md
```

## References

- [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://www.rfc-editor.org/rfc/rfc4271)
- [RFC 4272 - BGP Security Vulnerabilities Analysis](https://www.rfc-editor.org/rfc/rfc4272)
- [RFC 2918 - Route Refresh Capability for BGP-4](https://www.rfc-editor.org/rfc/rfc2918)
- [RFC 3065 - Autonomous System Confederations for BGP](https://www.rfc-editor.org/rfc/rfc3065)

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome. Please submit issues and pull requests on the project repository.
