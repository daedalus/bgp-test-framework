# BGP Adversarial Test Framework

A comprehensive RFC compliance testing framework for BGP v1 to v4 implementations.

## Intended Use

This tool is designed as an RFC compliance testing utility for researchers and network engineers evaluating BGP implementation conformance. While it includes tests for security-related protocol behaviors, it is primarily intended to assist in compliance verification and protocol analysis.

**Caveat**: This is an RFC compliance testing tool. It may assist security researchers in evaluating BGP implementations, but security assessment is not its primary purpose.

## Overview

This framework provides automated testing capabilities to identify protocol violations in BGPv4 implementations. It includes tests for message validation, path attributes, FSM behavior, security, and extensions like VPNs, EVPN, SR, and more.

## Features

- **59 Test Categories** with 500+ test cases
- **Comprehensive Coverage**: Tests based on 53+ RFC specifications
- **Multiple Output Formats**: JSON and YAML report generation
- **Configurable Testing**: YAML configuration for complex scenarios
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

### Run Specific Tests

```bash
bgp-test --target 192.168.1.1 --test-ids MH-001 MH-002
```

### Run Test Categories

```bash
bgp-test --target 192.168.1.1 --categories message_header open_message
```

### With Configuration File

```bash
bgp-test --config config.yaml
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

## Test Categories

### Core BGP (RFC 4271)

| Category | RFC | Tests |
|----------|-----|-------|
| `message_header` | 4271 §4.1, 6.1 | Message header validation |
| `open_message` | 4271 §4.2, 6.2 | OPEN message handling |
| `update_message` | 4271 §4.3, 6.3 | UPDATE message processing |
| `attribute` | 4271 §5 | Path attribute validation |
| `fsm` | 4271 §8 | Finite State Machine behavior |
| `timing` | 4271 §10 | Keepalive timing behavior |
| `security` | 4271 §6, 4272 | Security considerations |
| `route_aggregation` | 4271 §9.2.2 | Route aggregation |
| `decision_process` | 4271 §9.1 | Decision process |
| `keepalive_message` | 4271 §4.4 | KEEPALIVE handling |
| `notification_message` | 4271 §4.5 | NOTIFICATION handling |
| `version_negotiation` | 4271 §7 | Version negotiation |
| `connection_collision` | 4271 §6.8 | Collision detection |

### BGP Extensions

| Category | RFC | Tests |
|----------|-----|-------|
| `multiprotocol` | 2858 | Multiprotocol Extensions |
| `route_refresh` | 2918 | Route Refresh Capability |
| `graceful_restart` | 4724 | Graceful Restart Mechanism |
| `enhanced_route_refresh` | 7313 | Enhanced Route Refresh |
| `extended_messages` | 7606 | Extended Message Support |
| `orf_filtering` | 5291 | Outbound Route Filtering |
| `dynamic_capability` | 6724 | Dynamic Capability |
| `capabilities` | 2842 | Capability Advertisement |
| `route_reflection` | 4456 | Route Reflection |
| `confederation` | 3065 | AS Confederations |

### Address Families & VPNs

| Category | RFC | Tests |
|----------|-----|-------|
| `vpn` | 4364 | BGP/MPLS VPNs |
| `ipv6_vpn` | 4659 | IPv6 VPN Extension |
| `bgp_ls` | 7752 | Link-State Distribution |
| `bgp_ls_updated` | 9552 | BGP-LS Updated |
| `mpls_labels` | 3107 | MPLS Label Distribution |
| `mpls_label_binding` | 8277 | MPLS Label Binding |

### Communities & Attributes

| Category | RFC | Tests |
|----------|-----|-------|
| `communities` | 1997 | BGP Communities |
| `large_communities` | 8092 | Large Communities |
| `large_community_usage` | 8195 | Large Community Usage |
| `ipv6_extended_community` | 5701 | IPv6 Extended Community |
| `blackhole_community` | 7999 | BLACKHOLE Community |
| `nopeer` | 3765 | NOPEER Community |

### Security & Validation

| Category | RFC | Tests |
|----------|-----|-------|
| `as_number` | 1930, 6996 | AS Number handling |
| `as0_processing` | 7607 | AS 0 Processing |
| `as0_processing` | 7607 | AS 0 Processing |
| `origin_validation` | 6811 | Prefix Origin Validation |
| `rpki_router` | 6810 | RPKI to Router Protocol |
| `route_flap_damping` | 2439, 3345 | Route Flap Damping |
| `gtsm` | 5082 | TTL Security Mechanism |
| `flow_spec` | 5575 | Flow Specification |
| `admin_shutdown` | 8203 | Admin Shutdown Communication |
| `cease_notification` | 4486 | Cease Notification Subcodes |
| `route_oscillation` | 3345 | Route Oscillation |

### Advanced Features

| Category | RFC | Tests |
|----------|-----|-------|
| `graceful_shutdown` | 8326 | Graceful Shutdown |
| `evpn_nvo` | 8365 | EVPN NVO |
| `segment_routing` | 8402 | Segment Routing |
| `evpn_irb` | 9135 | EVPN IRB |
| `evpn_ip_prefix` | 9136 | EVPN IP Prefix (RT-5) |
| `bgp_role` | 9234 | BGP Role/OTC |
| `srv6_bgp_overlay` | 9252 | SRv6 BGP Overlay |
| `sr_policy` | 9256 | SR Policy |
| `datacenter_bgp` | 7938 | Data Center BGP |

### Protocol Updates

| Category | RFC | Tests |
|----------|-----|-------|
| `aigp` | 7311 | Accumulated IGP Metric |
| `extended_optional_parameters` | 9072 | Extended OP Length |
| `fsm_error_subcodes` | 6608 | FSM Error Subcodes |
| `bgp_identifier` | 6286 | AS-Wide Unique BGP ID |

## Programmatic API

```python
from bgp_test_framework.api import run_bgp_tests, BGPTestHarness, BGPTestConfig

# Quick start - run all tests
result = run_bgp_tests("192.168.1.1", 65001)
print(f"Compliance Score: {result['compliance_score']}%")

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
```

### Message Builder API

```python
from bgp_test_framework.api import BGPMessageBuilder

# Build messages
open_msg = BGPMessageBuilder.create_open(my_as=65001, hold_time=180)
keepalive = BGPMessageBuilder.create_keepalive()
route_refresh = BGPMessageBuilder.create_route_refresh(afi=1, safi=1)

# Build path attributes
origin = BGPMessageBuilder.create_origin_attribute("IGP")
as_path = BGPMessageBuilder.create_as_path_attribute([65001, 65002])
next_hop = BGPMessageBuilder.create_next_hop_attribute("192.168.1.1")
```

## Configuration File

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

test_ids:
  - MH-001
  - OP-001

# Output
output: "results.json"
format: "json"
verbose: true
```

## Output Format

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
      "message_header": {"total": 14, "passed": 14, "failed": 0}
    }
  },
  "results": [
    {
      "test_id": "MH-001",
      "test_name": "Invalid Marker",
      "category": "message_header",
      "passed": true,
      "expected_behavior": "Send OPEN with invalid marker",
      "actual_behavior": "NOTIFICATION received"
    }
  ]
}
```

## Testing Setup

This framework requires a BGP peer to test against.

### Option 1: Containerlab (Recommended)

```bash
# Install containerlab
curl -L https://containerlab.dev/install/ | bash

# Deploy FRR containers
containerlab deploy -t topology.yml

# Test the framework
bgp-test --target <router_ip> --as-number 65001

# Cleanup
containerlab destroy -t topology.yml
```

### Option 2: Docker

```bash
docker run -d --name bgp-peer frrouting/frr:latest
docker exec -it bgp-peer vtysh -c "configure terminal"
docker exec -it bgp-peer vtysh -c "router bgp 65001"
docker exec -it bgp-peer vtysh -c "neighbor 192.168.1.1 remote-as 65001"
bgp-test --target <container_ip> --as-number 65001
```

### Quick Test Without a BGP Peer

```python
from bgp_test_framework.api import BGPMessageBuilder, BGPTestHarness, BGPTestConfig

# Validate message generation
msg = BGPMessageBuilder.create_open(my_as=65001)

# Get available tests
config = BGPTestConfig(target_host="192.168.1.1", source_as=65001)
harness = BGPTestHarness(config)
tests = harness.get_all_tests("message_header")
```

## Development

### Running Tests

```bash
pytest tests/unit/
```

### Project Structure

```
bgp_test_framework/
├── src/bgp_test_framework/
│   ├── constants.py       # RFC constants
│   ├── messages.py        # BGP message parsing/building
│   ├── assessments.py     # Assessment cases (59 categories)
│   ├── runner.py           # Test execution engine
│   ├── api.py             # Programmatic API
│   └── cli.py             # CLI entry point
├── tests/unit/            # Unit tests
├── RFCs/                  # 53 BGP RFC specifications
├── config.yaml            # Example configuration
└── README.md
```

## Supported RFCs

### Core BGP
- RFC 4271 - BGP-4
- RFC 4272 - BGP Security

### Multiprotocol & Extensions
- RFC 2858, 4760 - Multiprotocol Extensions
- RFC 2918 - Route Refresh
- RFC 4724 - Graceful Restart
- RFC 7313 - Enhanced Route Refresh
- RFC 7606 - Extended Messages
- RFC 5291 - ORF Filtering
- RFC 6724 - Dynamic Capability
- RFC 2842 - Capabilities

### VPNs & MPLS
- RFC 2547, 4364 - BGP/MPLS VPNs
- RFC 4659 - IPv6 VPN
- RFC 3107 - MPLS Labels
- RFC 8277 - MPLS Label Binding

### Link-State
- RFC 7752 - BGP-LS
- RFC 9552 - BGP-LS Updated
- RFC 9161 - BGP-LS IS-IS SR

### Security & Validation
- RFC 6810 - RPKI to Router
- RFC 6811 - Origin Validation
- RFC 7607 - AS 0 Processing
- RFC 5082 - GTSM
- RFC 5575 - FlowSpec
- RFC 8203 - Admin Shutdown
- RFC 4486 - Cease Notification

### Communities
- RFC 1997 - Communities
- RFC 8092 - Large Communities
- RFC 8195 - Large Community Usage
- RFC 5701 - IPv6 Extended Community
- RFC 7999 - BLACKHOLE Community
- RFC 3765 - NOPEER

### EVPN & SR
- RFC 8365 - EVPN NVO
- RFC 9135 - EVPN IRB
- RFC 9136 - EVPN IP Prefix
- RFC 8402 - Segment Routing
- RFC 9252 - SRv6 Overlay
- RFC 9256 - SR Policy

### Other
- RFC 8326 - Graceful Shutdown
- RFC 9234 - BGP Role
- RFC 7311 - AIGP
- RFC 9072 - Extended OP Length
- RFC 6608 - FSM Error Subcodes
- RFC 6286 - BGP Identifier
- RFC 7938 - Data Center BGP

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome. Please submit issues and pull requests on the project repository.
