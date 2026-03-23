# BGP Test Framework Specification

## Project Overview

- **Project Name**: BGP Adversarial Test Framework
- **Type**: RFC Compliance Testing Tool
- **Core Functionality**: Automated testing of BGPv4 implementations against RFC specifications
- **Target Users**: Network engineers, researchers, and BGP implementation developers

## Architecture

### Core Components

1. **CLI** (`src/bgp_test_framework/cli.py`)
   - Command-line interface for running tests
   - Supports configuration via YAML files
   - Multiple output formats (JSON, YAML)

2. **Runner** (`src/bgp_test_framework/runner.py`)
   - Test execution engine
   - Manages TCP connections to target BGP peers
   - Generic test implementation for missing specific implementations
   - Result aggregation and reporting

3. **Assessments** (`src/bgp_test_framework/assessments.py`)
   - 58 assessment classes covering different RFC specifications
   - Each class implements specific test methods
   - Test cases defined with expected behaviors

4. **Messages** (`src/bgp_test_framework/messages.py`)
   - BGP message building functions
   - Path attribute creation helpers
   - NLRI encoding utilities

5. **Constants** (`src/bgp_test_framework/constants.py`)
   - BGP message types
   - Path attribute types
   - NOTIFICATION error codes and subcodes

### Test Categories (58 total)

| Category | Tests | RFC Base |
|----------|-------|----------|
| message_header | 14 | RFC 4271 Section 4.1 |
| open_message | 20 | RFC 4271 Section 4.2 |
| update_message | 30 | RFC 4271 Section 4.3 |
| attribute | 15 | RFC 4271 Section 5 |
| fsm | 15 | RFC 4271 Section 8 |
| timing | 10 | RFC 4271 Section 8 |
| security | 20 | RFC 4271 Section 8 |
| multiprotocol | 5 | RFC 4760 |
| communities | 10 | RFC 1997 |
| large_communities | 8 | RFC 8093 |
| route_aggregation | 8 | RFC 4271 Section 5.1.6 |
| decision_process | 18 | RFC 4271 Section 9 |
| keepalive_message | 6 | RFC 4271 Section 4.4 |
| notification_message | 6 | RFC 4271 Section 4.5 |
| version_negotiation | 6 | RFC 4271 Section 4.2 |
| connection_collision | 4 | RFC 4271 Section 7 |
| route_reflection | 5 | RFC 4456 |
| graceful_restart | 5 | RFC 4724 |
| enhanced_route_refresh | 5 | RFC 7313 |
| extended_messages | 5 | RFC 9072 |
| orf_filtering | 5 | RFC 5291 |
| dynamic_capability | 5 | RFC 5543 |
| route_flap_damping | 10 | RFC 2439 |
| as_number | 10 | RFC 6793 |
| vpn | 10 | RFC 4364 |
| capabilities | 8 | RFC 5492 |
| route_refresh | 10 | RFC 2918 |
| mpls_labels | 10 | RFC 3107 |
| nopeer | 5 | RFC 3765 |
| route_oscillation | 5 | RFC 4271 Section 9.2 |
| cease_notification | 10 | RFC 4271 Section 6.7 |
| ipv6_vpn | 10 | RFC 4659 |
| gtsm | 8 | RFC 5082 |
| flow_spec | 28 | RFC 5575 |
| ipv6_extended_community | 9 | RFC 5701 |
| rpki_router | 19 | RFC 6810 |
| origin_validation | 10 | RFC 6810 |
| as0_processing | 10 | RFC 6933 |
| bgp_ls_nlri | 20 | RFC 7752 |
| blackhole_community | 10 | RFC 7999 |
| admin_shutdown | 10 | RFC 8203 |
| mpls_label_binding | 10 | RFC 6514 |
| large_community_usage | 12 | RFC 8193 |
| datacenter_bgp | 10 | RFC 7938 |
| graceful_shutdown | 10 | RFC 8326 |
| evpn_nvo | 10 | RFC 8362 |
| segment_routing | 11 | RFC 8402 |
| evpn_irb | 10 | RFC 9136 |
| evpn_ip_prefix | 11 | RFC 9135 |
| bgp_role | 15 | RFC 9234 |
| srv6_bgp_overlay | 17 | RFC 9252 |
| sr_policy | 18 | RFC 9256 |
| bgp_ls_updated | 17 | RFC 9562 |
| aigp | 10 | RFC 7311 |
| extended_optional_parameters | 8 | RFC 9072 |
| fsm_error_subcodes | 8 | RFC 6608 |
| bgp_identifier | 10 | RFC 6286 |

## Test Execution Flow

1. **Connect**: Establish TCP connection to target BGP port
2. **Open Exchange**: Send OPEN message, receive response
3. **Keepalive Exchange**: Complete BGP session establishment
4. **Test Message**: Send malformed/problematic BGP message
5. **Validate Response**: Check for NOTIFICATION or session state

## Configuration

### config.yaml Structure

```yaml
target: "172.16.0.2"
port: 179
source_as: 65001
source_ip: "172.16.0.1"
bgp_id: "172.16.0.1"
hold_time: 180
timeout: 5.0
test_categories:
  - all
```

## Docker Deployment

### docker-compose.yml

The FRR container is configured as the target BGP implementation:

- Local AS: 65001
- Router-ID: 172.16.0.2
- Accepts connections from: 172.16.0.1, 172.16.0.3, 172.16.0.4 (AS 65000)
- Strict capability matching enabled

## Test Results

- **Total Tests**: 624
- **Expected Pass Rate**: ~53% (with FRR target)
- **0 Generic test - not implemented**: All tests have implementations

## Dependencies

- Python 3.8+
- PyYAML
- Python socket (stdlib)

## References

- RFC 4271: A Border Gateway Protocol 4 (BGP-4)
- RFC 4760: Multiprotocol Extensions for BGP-4
- RFC 1997: BGP Communities Attribute
- RFC 3065: Autonomous System Confederations for BGP
- RFC 6608: Subcodes for BGP FSM Error
- RFC 6286: BGP Identifier and Autonomous System Number Representation
- RFC 9072: Extended Optional Parameters for BGP
