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

## Testing Setup

This framework requires a BGP peer to test against. Below are options for setting up a test environment.

### Option 1: Containerlab (Recommended)

Containerlab provides a quick way to deploy containerized BGP routers:

```bash
# Install containerlab
curl -L https://containerlab.dev/install/ | bash

# Create topology file (topology.yml)
cat > topology.yml << 'EOF'
name: bgp_test
topology:
  kinds:
    linux:
      image: frrouting/frr:latest
  nodes:
    router1:
      kind: linux
      image: frrouting/frr:latest
      bgp:
        as: 65001
        neighbors:
          - name: router2
            as: 65002
    router2:
      kind: linux
      image: frrouting/frr:latest
      bgp:
        as: 65002
        neighbors:
          - name: router1
            as: 65001
  links:
    - endpoints: ["router1:eth1", "router2:eth1"]
EOF

# Deploy the lab
containerlab deploy -t topology.yml

# Get router IP
containerlab inspect -t topology.yml

# Test the framework
bgp-test --target <router_ip> --as-number 65001

# Destroy the lab when done
containerlab destroy -t topology.yml
```

### Option 2: Docker Containers

```bash
# Run FRR container
docker run -d --name bgp-peer frrouting/frr:latest

# Enter the container and configure BGP
docker exec -it bgp-peer vtysh -c "configure terminal"
docker exec -it bgp-peer vtysh -c "router bgp 65001"
docker exec -it bgp-peer vtysh -c "neighbor 192.168.1.1 remote-as 65001"
docker exec -it bgp-peer vtysh -c "end"
docker exec -it bgp-peer vtysh -c "write memory"

# Get container IP
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bgp-peer

# Test
bgp-test --target <container_ip> --as-number 65001
```

### Option 3: System Packages (Linux)

```bash
# Install FRR or BIRD
sudo apt install frr    # Debian/Ubuntu
sudo apt install bird    # Alternative

# Configure FRR
sudo vtysh -c "configure terminal"
sudo vtysh -c "router bgp 65001"
sudo vtysh -c "neighbor 192.168.1.1 remote-as 65001"
sudo vtysh -c "end"
sudo vtysh -c "write memory"

# Test
bgp-test --target 127.0.0.1 --as-number 65001
```

### Option 4: Virtual Machines

Download and install:
- **FRR**: https://frrouting.org/
- **BIRD**: https://bird.network.cz/
- **Cisco CSR1000V**: Commercial option
- **Juniper vSRX**: Commercial option

### Quick Test Without a BGP Peer

Use the programmatic API to validate message generation:

```python
from bgp_test_framework.api import BGPMessageBuilder, BGPParser

# Test message building
msg = BGPMessageBuilder.create_open(my_as=65001)
parsed = BGPParser.parse_header(msg)
print(f"Message type: {parsed['type']}")

# Test compliance scoring
from bgp_test_framework.api import BGPTestHarness, BGPTestConfig
config = BGPTestConfig(target_host="192.168.1.1", source_as=65001)
harness = BGPTestHarness(config)
tests = harness.get_all_tests("message_header")
print(f"Available tests: {len(tests)}")
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
│   ├── assessments.py     # Assessment case definitions (250+ tests)
│   ├── runner.py          # Test execution engine
│   ├── api.py             # Programmatic API
│   └── cli.py             # CLI entry point
├── tests/
│   ├── unit/              # Unit tests
│   └── functional/         # Functional tests
├── examples/              # Example setups
│   ├── containerlab/       # Containerlab topology
│   ├── docker/             # Docker Compose setup
│   └── test_example.py     # Python API example
├── RFCs/                  # RFC specification documents
│   ├── rfc1105.txt        # RFC 1105 (BGP v1, obsolete)
│   ├── rfc1163.txt        # RFC 1163 (BGP-2, obsolete)
│   ├── rfc1267.txt        # RFC 1267 (BGP-3, obsolete)
│   ├── rfc1771.txt        # RFC 1771 (BGP-4, obsolete)
│   ├── rfc1930.txt        # RFC 1930 (AS Number Guidelines)
│   ├── rfc1997.txt        # RFC 1997 (BGP Communities)
│   ├── rfc1998.txt        # RFC 1998 (Community in Multi-home)
│   ├── rfc2439.txt        # RFC 2439 (Route Flap Damping)
│   ├── rfc2858.txt        # RFC 2858 (Multiprotocol Extensions)
│   ├── rfc2918.txt        # RFC 2918 (Route Refresh)
│   ├── rfc3065.txt        # RFC 3065 (AS Confederations)
│   ├── rfc3345.txt        # RFC 3345 (Route Flap Damping)
│   ├── rfc4271.txt        # RFC 4271 (BGP-4)
│   ├── rfc4272.txt        # RFC 4272 (BGP Security)
│   └── rfc8092.txt        # RFC 8092 (BGP Large Communities)
├── config.yaml            # Example configuration
├── pyproject.toml        # Project configuration
└── README.md
```

### communities
Tests for BGP Communities attribute per RFC 1997:
- COMM-001: Well-Known NO_EXPORT Community
- COMM-002: Well-Known NO_ADVERTISE Community
- COMM-003: Well-Known NO_EXPORT_SUBCONFED Community
- COMM-004: Custom Community Format
- COMM-005: Multiple Communities
- COMM-006: Community Attribute Length Zero
- COMM-007: Community Value Reserved Range
- COMM-008: Community Value Reserved Upper Range
- COMM-009: Community Aggregation
- COMM-010: Community Propagation

### large_communities
Tests for BGP Large Communities attribute per RFC 8092:
- LCOMM-001: Large Community Attribute
- LCOMM-002: Large Community 12-Byte Value
- LCOMM-003: Multiple Large Communities
- LCOMM-004: Large Community Length Not Multiple of 12
- LCOMM-005: Large Community Reserved AS in Global Admin
- LCOMM-006: Large Community Duplicate Values
- LCOMM-007: Large Community Aggregation
- LCOMM-008: Large Community Attribute Zero Length
- LCOMM-009: Large Community Global Administrator AS4
- LCOMM-010: Large Community with Local Data Parts

### route_flap_damping
Tests for Route Flap Damping per RFC 2439 and RFC 3345:
- DAMP-001: Route Withdrawal Increment
- DAMP-002: Route Re-advertisement
- DAMP-003: Damping Threshold Exceeded
- DAMP-004: Route Reuse After Stability
- DAMP-005: Maximum Hold Time
- DAMP-006: Exponential Decay While Reachable
- DAMP-007: Exponential Decay While Unreachable
- DAMP-008: Rapid Route Flapping
- DAMP-009: IBGP vs EBGP Damping
- DAMP-010: Damping Parameter Persistence

### as_number
Tests for AS Number handling per RFC 1930 and RFC 6996:
- AS-001: AS 0 Rejection
- AS-002: Private AS 16-bit Range
- AS-003: Private AS 32-bit Range
- AS-004: AS 65535 Reserved
- AS-005: AS 4294967295 Reserved
- AS-006: Four-Octet AS Capability
- AS-007: AS_PATH with 4-Byte AS Numbers
- AS-008: AS4_AGGREGATOR Attribute
- AS-009: AS_PATH Loop with 4-Byte AS
- AS-010: Private AS Removal on EBGP

### multiprotocol
Tests for Multiprotocol Extensions per RFC 2858:
- MP-001: MP_REACH_NLRI Invalid AFI
- MP-002: MP_REACH_NLRI Invalid SAFI
- MP-003: MP_UNREACH_NLRI Invalid AFI
- MP-004: MP_REACH_NLRI IPv6
- MP-005: MP_REACH_NLRI VPNv4
- MP-006: MP_REACH_NLRI Next Hop Length Error
- MP-007: MP_REACH_NLRI Reserved SNPA
- MP-008: MP_REACH_NLRI Without Capability

### vpn
Tests for BGP/MPLS VPNs per RFC 2547 and RFC 4364:
- VPN-001: Route Distinguisher Type 0 Format
- VPN-002: Route Distinguisher Type 1 Format
- VPN-003: Route Distinguisher Type 2 Format
- VPN-004: VPN-IPv4 Address Encoding
- VPN-005: Route Target Extended Community
- VPN-006: Site of Origin Extended Community
- VPN-007: VPN Route With MPLS Label
- VPN-008: VPN-IPv4 AFI/SAFI Encoding
- VPN-009: VPN Route Distribution via IBGP
- VPN-010: Multiple Route Targets

### capabilities
Tests for Capability Advertisement per RFC 2842:
- CAP-001: Multiple Capabilities in Single OPEN
- CAP-002: Reserved Capability Code 0
- CAP-003: Capability with Wrong Length
- CAP-004: Duplicate Capability Codes
- CAP-005: Unsupported Capability Subcode
- CAP-006: Unknown Capability Code Handling
- CAP-007: Private Use Capability Codes
- CAP-008: 4-Byte AS Capability Code 65

### route_refresh
Tests for Route Refresh Capability per RFC 2918:
- RFR-001: Route Refresh Message Format
- RFR-002: Route Refresh with AFI/SAFI
- RFR-003: Route Refresh for IPv4 Unicast
- RFR-004: Route Refresh for IPv6 Unicast
- RFR-005: Route Refresh with Route Target ORF
- RFR-006: Route Refresh Response
- RFR-007: Route Refresh Without Capability
- RFR-008: Multiple Route Refresh Requests
- RFR-009: Route Refresh AFI/SAFI Not Advertised
- RFR-010: Route Refresh End-of-RIB

### mpls_labels
Tests for MPLS Label Distribution in BGP per RFC 3107:
- LABEL-001: MPLS Label in MP_REACH_NLRI SAFI-4
- LABEL-002: MPLS Label 3-Byte Encoding
- LABEL-003: MPLS Label Stack Depth
- LABEL-004: MPLS Label Reserved Range 0-15
- LABEL-005: MPLS Label Implicit NULL
- LABEL-006: MPLS Label Withdrawal Value
- LABEL-007: MPLS Label Next Hop Self
- LABEL-008: MPLS Label Preservation on Redistribute
- LABEL-009: MPLS Label NLRI Length Field
- LABEL-010: MPLS Label Capability Advertisement

### nopeer
Tests for NOPEER Community per RFC 3765:
- NOPEER-001: NOPEER Community Value (0xFFFFFF04)
- NOPEER-002: NOPEER Route Scope Control
- NOPEER-003: NOPEER vs NO_EXPORT Comparison
- NOPEER-004: NOPEER Well-Known Transitive
- NOPEER-005: NOPEER Filtering Implementation

### route_oscillation
Tests for BGP Route Oscillation Conditions per RFC 3345:
- OSCIL-001: Type I Oscillation with Route Reflection
- OSCIL-002: Type I Oscillation with Confederation
- OSCIL-003: MED Non-Deterministic Ordering
- OSCIL-004: Type II Oscillation Conditions
- OSCIL-005: MED Comparison Same AS Only

### cease_notification
Tests for BGP Cease Notification Message Subcodes per RFC 4486:
- CEASE-001: Maximum Number of Prefixes Reached
- CEASE-002: Administrative Shutdown
- CEASE-003: Peer De-configured
- CEASE-004: Administrative Reset
- CEASE-005: Connection Rejected
- CEASE-006: Other Configuration Change
- CEASE-007: Connection Collision Resolution
- CEASE-008: Out of Resources
- CEASE-009: Cease with Optional Data (Max Prefixes)
- CEASE-010: Cease Unknown Subcode

### ipv6_vpn
Tests for BGP-MPLS IP VPN Extension for IPv6 VPN per RFC 4659:
- V6VPN-001: VPN-IPv6 Route Advertisement
- V6VPN-002: VPN-IPv6 Labeled Route
- V6VPN-003: VPN-IPv6 with Unspecified Address
- V6VPN-004: VPN-IPv6 Prefix Encoding
- V6VPN-RD-*: Route Distinguisher Type 0/1/2 tests
- V6VPN-NH-*: Next Hop Encoding tests (Global, Link-Local, IPv4-mapped)

### gtsm
Tests for Generalized TTL Security Mechanism per RFC 5082:
- GTSM-255: TTL=255 for Single Hop
- GTSM-254: TTL=254 Multi-Hop Rejection
- GTSM-001: GTSM Single Hop Verification
- GTSM-002: GTSM Multi-Hop Rejection
- GTSM-003: GTSM ICMP Error Handling
- GTSM-*: Various TTL Values (0, 1, 64, 254, 255)

### flow_spec
Tests for Dissemination of Flow Specification Rules per RFC 5575:
- FSPEC-001: FlowSpec Basic Match (Destination Prefix)
- FSPEC-002: FlowSpec Port Match
- FSPEC-003: FlowSpec Protocol Match
- FSPEC-004: FlowSpec TCP Flags Match
- FSPEC-005: FlowSpec DSCP Match
- FSPEC-006: FlowSpec Fragment Match
- FSPEC-007: FlowSpec Combined Match
- FSPEC-008: FlowSpec Validation
- FSPEC-133: IPv4 FlowSpec (AFI=1, SAFI=133)
- FSPEC-134: VPNv4 FlowSpec (AFI=1, SAFI=134)
- FSPEC-COMP-*: Component Type Tests (Types 1-12)
- FSPEC-ACTION-*: Action Type Tests (traffic-rate, traffic-action, redirect, traffic-marking)

### ipv6_extended_community
Tests for IPv6 Address Specific Extended Community per RFC 5701:
- V6EC-0002: IPv6 Extended Community: Route Target
- V6EC-0003: IPv6 Extended Community: Route Origin
- V6EC-001: IPv6 Extended Community Length Validation (20 octets)
- V6EC-002: IPv6 Route Target with 2-byte AS Specific
- V6EC-003: IPv6 Route Target with 4-byte AS
- V6EC-004: IPv6 Route Origin with 2-byte AS Specific
- V6EC-005: IPv6 Route Origin with 4-byte AS
- V6EC-006: IPv6 Extended Community Global Administrator Field
- V6EC-007: IPv6 Extended Community Reserved Subtype

### rpki_router
Tests for RPKI to Router Protocol per RFC 6810:
- RPKI-000: Serial Notify PDU
- RPKI-001: Serial Query PDU
- RPKI-002: Reset Query PDU
- RPKI-003: Cache Response PDU
- RPKI-004: IPv4 Prefix PDU
- RPKI-006: IPv6 Prefix PDU
- RPKI-007: End of Data PDU
- RPKI-008: Error Report PDU
- RPKI-009: RPKI PDU Header Format
- RPKI-010: RPKI Length Field Validation

### origin_validation
Tests for BGP Prefix Origin Validation per RFC 6811:
- OV-000: Origin Validation State: NOT_FOUND
- OV-001: Origin Validation State: VALID
- OV-002: Origin Validation State: INVALID
- OV-003: Origin Validation Route with Validated ROA
- OV-004: Origin Validation Route without ROA (NOT_FOUND)
- OV-005: Origin Validation Invalid Origin AS
- OV-006: Origin Validation Max Length Exceeded
- OV-007: Origin Validation Exact Match
- OV-008: Origin Validation with AS_PATH

### as0_processing
Tests for AS 0 Processing per RFC 7607:
- AS0-001: AS 0 in OPEN Message (must reject)
- AS0-002: AS 0 in AS_PATH (must reject)
- AS0-003: AS 0 in AS4_AGGREGATOR
- AS0-004: AS 0 in AGGREGATOR Attribute
- AS0-005: AS 0 Leading in AS_PATH
- AS0-006: AS 0 in AS_SET
- AS0-007: AS 0 in AS_CONFED_SEQUENCE
- AS0-008: AS 0 in AS_CONFED_SET
- AS0-009: AS 0 Propagation Prevention
- AS0-010: AS 0 with Valid Routes

### bgp_ls
Tests for BGP Link-State Distribution per RFC 7752:
- BGPLS-001: BGP-LS AFI/SAFI Values (AFI=16388, SAFI=71/72)
- BGPLS-002: BGP-LS Node NLRI
- BGPLS-003: BGP-LS Link NLRI
- BGPLS-004: BGP-LS IPv4 Prefix NLRI
- BGPLS-005: BGP-LS IPv6 Prefix NLRI
- BGPLS-006: BGP-LS Node Descriptor TLVs
- BGPLS-007: BGP-LS Link Descriptor TLVs
- BGPLS-008: BGP-LS Prefix Descriptor TLVs
- BGPLS-009: BGP-LS Capability Advertisement
- BGPLS-010: BGP-LS VPN SAFI
- BGPLS-NLRI-*: NLRI Type Tests (Node=1, Link=2, IPv4 Prefix=3, IPv6 Prefix=4)
- BGPLS-PROT-*: Protocol ID Tests (IS-IS, OSPF, Direct, Static, OSPFv3)

### blackhole_community
Tests for BLACKHOLE Community per RFC 7999:
- BH-001: BLACKHOLE Community Value (0xFFFF029A)
- BH-002: BLACKHOLE IPv4 /32 Prefix
- BH-003: BLACKHOLE IPv6 /128 Prefix
- BH-004: BLACKHOLE with NO_EXPORT Scope
- BH-005: BLACKHOLE with NO_ADVERTISE Scope
- BH-006: BLACKHOLE with NO_EXPORT_SUBCONFED
- BH-007: BLACKHOLE Action Implementation
- BH-008: BLACKHOLE Prefix Length /24 IPv4
- BH-009: BLACKHOLE Authorization Validation
- BH-010: BLACKHOLE with Multiple Scoping Communities

### admin_shutdown
Tests for BGP Administrative Shutdown Communication per RFC 8203:
- AS-001: Admin Shutdown with UTF-8 Message
- AS-002: Admin Shutdown Zero Length
- AS-003: Admin Shutdown Max Length (128)
- AS-004: Admin Reset with Message
- AS-005: Admin Shutdown Multiline UTF-8
- AS-006: Admin Shutdown Unicode Content
- AS-007: Admin Shutdown Reserved Subcode
- AS-008: Admin Shutdown Syslog Format
- AS-009: Admin Shutdown with Error Data
- AS-010: Admin Reset Backward Compatibility

### mpls_label_binding
Tests for MPLS Label Binding to Address Prefixes per RFC 8277:
- MLB-001: Single MPLS Label SAFI-4
- MLB-002: Single MPLS Label SAFI-128
- MLB-003: Multiple Labels Capability
- MLB-004: Label Binding Advertisement
- MLB-005: Label Withdrawal with Compatibility
- MLB-006: Label Encoding Single Label
- MLB-007: Label Propagation No NH Change
- MLB-008: Label Propagation NH Change
- MLB-009: IPv6 Labeled Unicast SAFI-4
- MLB-010: Label Count Min Validation

### large_community_usage
Tests for BGP Large Community Usage per RFC 8195:
- LCU-FUNC-01: Large Community Function: ISO 3166-1 Country
- LCU-FUNC-02: Large Community Function: UN M49 Region
- LCU-FUNC-03: Large Community Function: Relation
- LCU-FUNC-04: Large Community Function: ASN Selective NO_EXPORT
- LCU-FUNC-05: Large Community Function: Location Selective NO_EXPORT
- LCU-FUNC-06: Large Community Function: ASN Prepend
- LCU-FUNC-07: Large Community Function: Location Prepend
- LCU-001: Selective NO_EXPORT by ASN
- LCU-002: Selective NO_EXPORT by Country
- LCU-003: AS Prepend by ASN
- LCU-004: Route Server Control
- LCU-005: Route Preference Communities

### datacenter_bgp
Tests for BGP in Large-Scale Data Centers per RFC 7938:
- DCB-001: Single-Hop EBGP Session
- DCB-002: Private ASN Usage
- DCB-003: Four-Octet ASN in Data Center
- DCB-004: Allowas-in Feature
- DCB-005: Remove Private AS Feature
- DCB-006: Basic ECMP Behavior
- DCB-007: Multipath Relax
- DCB-008: AS_PATH Loop Detection DC
- DCB-009: Route Advertisement No Summarization
- DCB-010: ECMP with Link Bandwidth

## References

- [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://www.rfc-editor.org/rfc/rfc4271)
- [RFC 4272 - BGP Security Vulnerabilities Analysis](https://www.rfc-editor.org/rfc/rfc4272)
- [RFC 2918 - Route Refresh Capability for BGP-4](https://www.rfc-editor.org/rfc/rfc2918)
- [RFC 3065 - Autonomous System Confederations for BGP](https://www.rfc-editor.org/rfc/rfc3065)
- [RFC 4724 - Graceful Restart Mechanism for BGP](https://www.rfc-editor.org/rfc/rfc4724)
- [RFC 7313 - Enhanced Route Refresh Capability for BGP-4](https://www.rfc-editor.org/rfc/rfc7313)
- [RFC 4760 - Multiprotocol Extensions for BGP-4](https://www.rfc-editor.org/rfc/rfc4760)
- [RFC 2858 - Multiprotocol Extensions for BGP-4](https://www.rfc-editor.org/rfc/rfc2858)
- [RFC 4456 - Route Reflection](https://www.rfc-editor.org/rfc/rfc4456)
- [RFC 4893 - BGP Support for Four-Octet AS Number Space](https://www.rfc-editor.org/rfc/rfc4893)
- [RFC 1997 - BGP Communities Attribute](https://www.rfc-editor.org/rfc/rfc1997)
- [RFC 8092 - BGP Large Communities Attribute](https://www.rfc-editor.org/rfc/rfc8092)
- [RFC 1930 - Guidelines for Creation, Selection, and Registration of an AS](https://www.rfc-editor.org/rfc/rfc1930)
- [RFC 2439 - BGP Route Flap Damping](https://www.rfc-editor.org/rfc/rfc2439)
- [RFC 3345 - Border Gateway Protocol Route Flap Damping](https://www.rfc-editor.org/rfc/rfc3345)
- [RFC 6996 - Private Autonomous System (AS) Numbers for BGP](https://www.rfc-editor.org/rfc/rfc6996)
- [RFC 2547 - BGP/MPLS IP Virtual Private Networks (VPNs)](https://www.rfc-editor.org/rfc/rfc2547)
- [RFC 4364 - BGP/MPLS IP Virtual Private Networks (VPNs)](https://www.rfc-editor.org/rfc/rfc4364)
- [RFC 2842 - Capabilities Advertisement with BGP-4](https://www.rfc-editor.org/rfc/rfc2842)
- [RFC 5492 - Extensions to BGP-4 for Capabilities Advertisement](https://www.rfc-editor.org/rfc/rfc5492)
- [RFC 3107 - Carrying Label Information in BGP-4](https://www.rfc-editor.org/rfc/rfc3107)
- [RFC 3765 - NOPEER Community for BGP Route Scope Control](https://www.rfc-editor.org/rfc/rfc3765)
- [RFC 4486 - Subcodes for BGP Cease Notification Message](https://www.rfc-editor.org/rfc/rfc4486)
- [RFC 4659 - BGP-MPLS IP VPN Extension for IPv6 VPN](https://www.rfc-editor.org/rfc/rfc4659)
- [RFC 5082 - The Generalized TTL Security Mechanism (GTSM)](https://www.rfc-editor.org/rfc/rfc5082)
- [RFC 5575 - Dissemination of Flow Specification Rules](https://www.rfc-editor.org/rfc/rfc5575)
- [RFC 5701 - IPv6 Address Specific Extended Community](https://www.rfc-editor.org/rfc/rfc5701)
- [RFC 6810 - The RPKI to Router Protocol](https://www.rfc-editor.org/rfc/rfc6810)
- [RFC 6811 - BGP Prefix Origin Validation](https://www.rfc-editor.org/rfc/rfc6811)
- [RFC 7607 - Codification of AS 0 Processing](https://www.rfc-editor.org/rfc/rfc7607)
- [RFC 7752 - North-Bound Distribution of Link-State and TE Information](https://www.rfc-editor.org/rfc/rfc7752)
- [RFC 7938 - Use of BGP for Routing in Large-Scale Data Centers](https://www.rfc-editor.org/rfc/rfc7938)
- [RFC 7999 - BLACKHOLE Community](https://www.rfc-editor.org/rfc/rfc7999)
- [RFC 8195 - Use of BGP Large Communities](https://www.rfc-editor.org/rfc/rfc8195)
- [RFC 8203 - BGP Administrative Shutdown Communication](https://www.rfc-editor.org/rfc/rfc8203)
- [RFC 8277 - Using BGP to Bind MPLS Labels to Address Prefixes](https://www.rfc-editor.org/rfc/rfc8277)
- [RFC 1105 - BGP (obsolete)](https://www.rfc-editor.org/rfc/rfc1105)
- [RFC 1163 - BGP-2 (obsolete)](https://www.rfc-editor.org/rfc/rfc1163)
- [RFC 1267 - BGP-3 (obsolete)](https://www.rfc-editor.org/rfc/rfc1267)
- [RFC 1771 - BGP-4 (obsolete)](https://www.rfc-editor.org/rfc/rfc1771)

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome. Please submit issues and pull requests on the project repository.
