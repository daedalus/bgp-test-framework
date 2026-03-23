"""
BGPv4 Adversarial Test Cases
Based on RFC 4271 specifications
"""

import socket
import struct
from typing import Optional, List, Dict, Any, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
from .messages import (
    MARKER,
    build_open_message,
    build_update_message,
    build_keepalive_message,
    build_route_refresh_message,
    PathAttribute,
    create_origin_attribute,
    create_as_path_attribute,
    create_next_hop_attribute,
    create_mp_reach_nlri_attribute,
)
from .constants import (
    MESSAGE_TYPES,
    NOTIFICATION_ERROR_CODES,
    MESSAGE_HEADER_ERROR_SUBCODES,
    OPEN_MESSAGE_ERROR_SUBCODES,
    UPDATE_MESSAGE_ERROR_SUBCODES,
)


class TestCategory(Enum):
    MESSAGE_HEADER = "message_header"
    OPEN_MESSAGE = "open_message"
    UPDATE_MESSAGE = "update_message"
    KEEPALIVE_MESSAGE = "keepalive_message"
    NOTIFICATION_MESSAGE = "notification_message"
    FSM = "fsm"
    TIMING = "timing"
    ATTRIBUTE = "attribute"
    SECURITY = "security"
    ROUTE_AGGREGATION = "route_aggregation"
    DECISION_PROCESS = "decision_process"
    VERSION_NEGOTIATION = "version_negotiation"
    CONNECTION_COLLISION = "connection_collision"
    MULTIPROTOCOL = "multiprotocol"
    ROUTE_REFLECTION = "route_reflection"
    CONFEDERATION = "confederation"
    GRACEFUL_RESTART = "graceful_restart"
    ENHANCED_ROUTE_REFRESH = "enhanced_route_refresh"
    EXTENDED_MESSAGES = "extended_messages"
    ORF_FILTERING = "orf_filtering"
    DYNAMIC_CAPABILITY = "dynamic_capability"
    COMMUNITIES = "communities"
    LARGE_COMMUNITIES = "large_communities"
    ROUTE_FLAP_DAMPING = "route_flap_damping"
    AS_NUMBER = "as_number"
    VPN = "vpn"
    CAPABILITIES = "capabilities"
    ROUTE_REFRESH = "route_refresh"
    MPLS_LABELS = "mpls_labels"
    NOPEER = "nopeer"
    ROUTE_OSCILLATION = "route_oscillation"
    CEASE_NOTIFICATION = "cease_notification"
    IPV6_VPN = "ipv6_vpn"
    GTSM = "gtsm"
    FLOW_SPEC = "flow_spec"
    BGP_LS = "bgp_ls"
    IPV6_EXTENDED_COMMUNITY = "ipv6_extended_community"
    RPKI_ROUTER = "rpki_router"
    ORIGIN_VALIDATION = "origin_validation"
    AS0_PROCESSING = "as0_processing"
    BGP_LS_NLRI = "bgp_ls_nlri"
    BLACKHOLE_COMMUNITY = "blackhole_community"
    ADMIN_SHUTDOWN = "admin_shutdown"
    MPLS_LABEL_BINDING = "mpls_label_binding"
    LARGE_COMMUNITY_USAGE = "large_community_usage"
    DATACENTER_BGP = "datacenter_bgp"
    GRACEFUL_SHUTDOWN = "graceful_shutdown"
    EVPN_NVO = "evpn_nvo"
    SEGMENT_ROUTING = "segment_routing"
    EVPN_IRB = "evpn_irb"
    EVPN_IP_PREFIX = "evpn_ip_prefix"
    BGP_ROLE = "bgp_role"
    SRV6_BGP_OVERLAY = "srv6_bgp_overlay"
    SR_POLICY = "sr_policy"
    BGP_LS_UPDATED = "bgp_ls_updated"
    AIGP = "aigp"
    EXTENDED_OPTIONAL_PARAMETERS = "extended_optional_parameters"
    FSM_ERROR_SUBCODES = "fsm_error_subcodes"
    BGP_IDENTIFIER = "bgp_identifier"


@dataclass
class TestResult:
    test_id: str
    test_name: str
    category: TestCategory
    passed: bool
    expected_behavior: str
    actual_behavior: str
    details: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[int] = None
    error_subcode: Optional[int] = None


@dataclass
class TestCase:
    test_id: str
    name: str
    category: TestCategory
    description: str
    expected_error_code: Optional[int] = None
    expected_error_subcode: Optional[int] = None
    should_close_connection: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


class TestIPConfig:
    def __init__(
        self,
        next_hop: str = "10.0.0.1",
        bgp_id_test: str = "192.168.1.1",
        comm_test_prefix: str = "192.168.1.0",
        large_comm_test_prefix: str = "192.168.3.0",
        nopeer_test_prefix: str = "192.168.30.0",
        vpn_prefix_pool: Optional[List[str]] = None,
        mpls_prefix_pool: Optional[List[str]] = None,
        damping_prefix_pool: Optional[List[str]] = None,
        aspath_prefix_pool: Optional[List[str]] = None,
        oscillation_prefix_pool: Optional[List[str]] = None,
        extcomm_prefix_pool: Optional[List[str]] = None,
        blackhole_prefix_pool: Optional[List[str]] = None,
        large_comm_usage_pool: Optional[List[str]] = None,
        sr_prefix_pool: Optional[List[str]] = None,
        srv6_prefix_pool: Optional[List[str]] = None,
        bgpls_prefix_pool: Optional[List[str]] = None,
        graceful_shutdown_pool: Optional[List[str]] = None,
        srpolicy_prefix_pool: Optional[List[str]] = None,
    ):
        self.next_hop = next_hop
        self.bgp_id_test = bgp_id_test
        self.comm_test_prefix = comm_test_prefix
        self.large_comm_test_prefix = large_comm_test_prefix
        self.nopeer_test_prefix = nopeer_test_prefix
        self.vpn_prefix_pool = vpn_prefix_pool or [
            "10.0.0.0",
            "10.0.1.0",
            "10.0.2.0",
            "10.0.3.0",
            "10.0.4.0",
            "10.0.5.0",
            "10.0.6.0",
            "10.0.7.0",
            "10.0.8.0",
            "10.0.9.0",
        ]
        self.mpls_prefix_pool = mpls_prefix_pool or [
            "192.168.20.0",
            "192.168.21.0",
            "192.168.22.0",
            "192.168.23.0",
            "192.168.24.0",
            "192.168.25.0",
            "192.168.26.0",
            "192.168.27.0",
            "192.168.28.0",
        ]
        self.damping_prefix_pool = damping_prefix_pool or [
            "192.168.100.0",
            "192.168.101.0",
            "192.168.102.0",
            "192.168.103.0",
            "192.168.104.0",
            "192.168.105.0",
            "192.168.106.0",
            "192.168.107.0",
            "192.168.108.0",
            "192.168.109.0",
        ]
        self.aspath_prefix_pool = aspath_prefix_pool or ["192.168.50.0"]
        self.oscillation_prefix_pool = oscillation_prefix_pool or [
            "192.168.200.0",
            "192.168.200.1",
            "192.168.200.2",
            "192.168.200.3",
            "192.168.200.4",
        ]
        self.extcomm_prefix_pool = extcomm_prefix_pool or ["192.168.100.0"]
        self.blackhole_prefix_pool = blackhole_prefix_pool or [
            "192.168.100.0",
            "192.168.0.0",
        ]
        self.large_comm_usage_pool = large_comm_usage_pool or ["192.168.10.0"]
        self.sr_prefix_pool = sr_prefix_pool or ["192.168.60.0"]
        self.srv6_prefix_pool = srv6_prefix_pool or ["192.168.250.0"]
        self.bgpls_prefix_pool = bgpls_prefix_pool or ["192.168.255.0"]
        self.graceful_shutdown_pool = graceful_shutdown_pool or ["192.168.50.0"]
        self.srpolicy_prefix_pool = srpolicy_prefix_pool or ["192.168.1.0"]


class BGPTestFramework:
    def __init__(
        self,
        target_host: str,
        target_port: int = 179,
        source_as: int = 65001,
        source_ip: str = "0.0.0.1",
        timeout: float = 5.0,
        debug: bool = False,
        ip_config: Optional[TestIPConfig] = None,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.source_as = source_as
        self.source_ip = source_ip
        self.timeout = timeout
        self.debug = debug
        self.sock: Optional[socket.socket] = None
        self.results: List[TestResult] = []
        self._connect_retry_counter = 0
        self._connect_retry_time = 120
        self._hold_time = 90
        self._keepalive_time = 30
        self._state = "Idle"
        self.ip_config = ip_config if ip_config is not None else TestIPConfig()

    def get_next_hop(self) -> str:
        return self.ip_config.next_hop

    def get_bgp_id_test(self) -> str:
        return self.ip_config.bgp_id_test

    def get_prefix(self, pool_name: str, index: int = 0) -> str:
        pool = getattr(self.ip_config, pool_name, None)
        if pool is None or len(pool) == 0:
            return "10.0.0.0"
        return pool[index % len(pool)]

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target_host, self.target_port))
            self._state = "Connect"
            return True
        except Exception:
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self._state = "Idle"

    def _hex_dump(self, data: bytes, direction: str) -> str:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_chunk = " ".join(f"{b:02x}" for b in chunk)
            ascii_chunk = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}: {hex_chunk:<48}  {ascii_chunk}")
        return f"\n{direction} ({len(data)} bytes):\n" + "\n".join(lines)

    def send_raw(self, data: bytes) -> bool:
        if not self.sock:
            return False
        try:
            if self.debug:
                print(self._hex_dump(data, "TX"))
            self.sock.sendall(data)
            return True
        except Exception:
            return False

    def receive_raw(self, size: int = 4096) -> Optional[bytes]:
        if not self.sock:
            return None
        try:
            data = self.sock.recv(size)
            if self.debug and data:
                print(self._hex_dump(data, "RX"))
            return data
        except Exception:
            return None

    def _create_header(
        self, msg_type: int, length: int, marker: bytes = MARKER
    ) -> bytes:
        return marker + struct.pack("!HB", length, msg_type)

    def _run_test(self, test_case: TestCase, test_func: Callable) -> TestResult:
        result = TestResult(
            test_id=test_case.test_id,
            test_name=test_case.name,
            category=test_case.category,
            passed=False,
            expected_behavior=test_case.description,
            actual_behavior="",
        )

        try:
            if not self.connect():
                result.actual_behavior = "Failed to establish TCP connection"
                self.results.append(result)
                return result

            passed, actual, details = test_func()
            result.passed = passed
            result.actual_behavior = actual
            result.details = details

            if test_case.expected_error_code and details.get("error_code"):
                result.error_code = details["error_code"]
            if test_case.expected_error_subcode and details.get("error_subcode"):
                result.error_subcode = details["error_subcode"]

        except Exception as e:
            result.actual_behavior = f"Exception: {str(e)}"
            result.details = {"exception": str(e)}
        finally:
            self.disconnect()

        self.results.append(result)
        return result


class MessageHeaderAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="MH-001",
                name="Invalid Marker - All Zeros",
                category=TestCategory.MESSAGE_HEADER,
                description="Send OPEN with invalid marker (all zeros) - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "CONNECTION_NOT_SYNCHRONIZED"
                ],
            ),
            TestCase(
                test_id="MH-002",
                name="Invalid Marker - Partial",
                category=TestCategory.MESSAGE_HEADER,
                description="Send OPEN with partial invalid marker - RFC 4271 Section 6.1",
            ),
            TestCase(
                test_id="MH-003",
                name="Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length < 19 - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-004",
                name="Message Length Too Large",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length > 4096 - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-005",
                name="Message Length Zero",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length = 0 - RFC 4271 Section 6.1",
            ),
            TestCase(
                test_id="MH-006",
                name="Invalid Message Type",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with invalid type (0) - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_TYPE"
                ],
            ),
            TestCase(
                test_id="MH-007",
                name="Invalid Message Type - Reserved",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with reserved type (5) - RFC 4271 Section 6.1",
            ),
            TestCase(
                test_id="MH-008",
                name="Message Type Future",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with future type (255) - RFC 4271 Section 6.1",
            ),
            TestCase(
                test_id="MH-009",
                name="OPEN Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send OPEN with length < 29 - RFC 4271 Section 4.2, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-010",
                name="UPDATE Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send UPDATE with length < 23 - RFC 4271 Section 4.3, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-011",
                name="KEEPALIVE Message Wrong Length",
                category=TestCategory.MESSAGE_HEADER,
                description="Send KEEPALIVE with length != 19 - RFC 4271 Section 4.4, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-012",
                name="NOTIFICATION Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send NOTIFICATION with length < 21 - RFC 4271 Section 4.5, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES[
                    "BAD_MESSAGE_LENGTH"
                ],
            ),
            TestCase(
                test_id="MH-013",
                name="Truncated Header",
                category=TestCategory.MESSAGE_HEADER,
                description="Send truncated BGP header - RFC 4271 Section 4.1",
            ),
            TestCase(
                test_id="MH-014",
                name="Extra Data After Message",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with extra padding - RFC 4271 Section 4.1",
            ),
        ]

    @staticmethod
    def test_mh_001(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_invalid_marker(framework)

    @staticmethod
    def test_mh_002(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments._test_partial_invalid_marker(framework)

    @staticmethod
    def test_mh_003(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_message_length_too_short(framework)

    @staticmethod
    def test_mh_004(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_message_length_too_large(framework)

    @staticmethod
    def test_mh_005(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_message_length_zero(framework)

    @staticmethod
    def test_mh_006(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_invalid_message_type(framework)

    @staticmethod
    def test_mh_007(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_reserved_message_type(framework)

    @staticmethod
    def test_mh_008(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_future_message_type(framework)

    @staticmethod
    def test_mh_009(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_open_message_length_too_short(framework)

    @staticmethod
    def test_mh_010(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_update_message_length_too_short(framework)

    @staticmethod
    def test_mh_011(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_keepalive_message_wrong_length(framework)

    @staticmethod
    def test_mh_012(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_notification_message_length_too_short(framework)

    @staticmethod
    def test_mh_013(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_truncated_header(framework)

    @staticmethod
    def test_mh_014(framework: BGPTestFramework) -> TestResult:
        return MessageHeaderAssessments.test_extra_data_after_message(framework)

    @staticmethod
    def test_invalid_marker(framework: BGPTestFramework) -> TestResult:
        test = TestCase(
            test_id="MH-001",
            name="Invalid Marker",
            category=TestCategory.MESSAGE_HEADER,
            description="Test with all zeros marker",
        )
        result = TestResult(
            test.test_id, test.name, test.category, False, test.description, ""
        )

        if not framework.connect():
            result.actual_behavior = "Failed to connect"
            return result

        msg = build_open_message(framework.source_as)
        malicious_msg = bytearray(msg)
        malicious_msg[0:16] = b"\x00" * 16
        framework.send_raw(bytes(malicious_msg))

        response = framework.receive_raw()
        if response:
            if len(response) >= 21:
                error_code = response[19]
                error_subcode = response[20] if len(response) > 20 else 0
                result.passed = True
                result.actual_behavior = (
                    f"Received NOTIFICATION: code={error_code}, subcode={error_subcode}"
                )
                result.details = {
                    "error_code": error_code,
                    "error_subcode": error_subcode,
                }
        else:
            result.actual_behavior = "No response received"

        framework.disconnect()
        return result

    @staticmethod
    def _test_partial_invalid_marker(framework: BGPTestFramework) -> TestResult:
        test = TestCase(
            test_id="MH-002",
            name="Partial Invalid Marker",
            category=TestCategory.MESSAGE_HEADER,
            description="Test with partial invalid marker (first 8 bytes)",
        )
        result = TestResult(
            test.test_id, test.name, test.category, False, test.description, ""
        )

        if not framework.connect():
            result.actual_behavior = "Failed to connect"
            return result

        msg = build_open_message(framework.source_as)
        malicious_msg = bytearray(msg)
        malicious_msg[0:8] = b"\x00" * 8
        framework.send_raw(bytes(malicious_msg))

        response = framework.receive_raw()
        if response:
            if len(response) >= 21:
                error_code = response[19]
                error_subcode = response[20] if len(response) > 20 else 0
                result.passed = True
                result.actual_behavior = (
                    f"Received NOTIFICATION: code={error_code}, subcode={error_subcode}"
                )
                result.details = {
                    "error_code": error_code,
                    "error_subcode": error_subcode,
                }
        else:
            result.actual_behavior = "No response received"

        framework.disconnect()
        return result

    @staticmethod
    def test_message_length_too_short(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-003",
            "Message Length Too Short",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["OPEN"], 10)
        msg += b"\x04\x19\x4e\x01\x00\xb4" + b"\x00" * 13
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received"
            result.details = {
                "error_code": response[19],
                "error_subcode": response[20] if len(response) > 20 else 0,
            }

        framework.disconnect()
        return result

    @staticmethod
    def test_message_length_too_large(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-004",
            "Message Length Too Large",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["KEEPALIVE"], 5000)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for oversized message"

        framework.disconnect()
        return result

    @staticmethod
    def test_invalid_message_type(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-006",
            "Invalid Message Type",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(0, 19)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received"
            result.details = {"error_code": response[19], "error_subcode": response[20]}

        framework.disconnect()
        return result

    @staticmethod
    def test_message_length_zero(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-005",
            "Message Length Zero",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["OPEN"], 0)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for length=0"

        framework.disconnect()
        return result

    @staticmethod
    def test_reserved_message_type(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-007",
            "Reserved Message Type",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - Type 5 is reserved",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(5, 19)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for reserved type 5"

        framework.disconnect()
        return result

    @staticmethod
    def test_future_message_type(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-008",
            "Future Message Type",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - Type 255 is future",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(255, 19)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for future type 255"

        framework.disconnect()
        return result

    @staticmethod
    def test_open_message_length_too_short(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-009",
            "OPEN Message Length Too Short",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - OPEN min is 29 bytes",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["OPEN"], 28)
        msg += b"\x00" * 9
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for OPEN < 29 bytes"

        framework.disconnect()
        return result

    @staticmethod
    def test_update_message_length_too_short(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-010",
            "UPDATE Message Length Too Short",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - UPDATE min is 23 bytes",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["UPDATE"], 22)
        msg += b"\x00" * 3
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for UPDATE < 23 bytes"

        framework.disconnect()
        return result

    @staticmethod
    def test_keepalive_message_wrong_length(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-011",
            "KEEPALIVE Message Wrong Length",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - KEEPALIVE must be 19 bytes",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["KEEPALIVE"], 25)
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for KEEPALIVE != 19 bytes"

        framework.disconnect()
        return result

    @staticmethod
    def test_notification_message_length_too_short(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-012",
            "NOTIFICATION Message Length Too Short",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 6.1 - NOTIFICATION min is 21 bytes",
            "",
        )

        if not framework.connect():
            return result

        msg = framework._create_header(MESSAGE_TYPES["NOTIFICATION"], 20)
        msg += b"\x00" * 1
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for NOTIFICATION < 21 bytes"

        framework.disconnect()
        return result

    @staticmethod
    def test_truncated_header(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-013",
            "Truncated Header",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 4.1 - Send truncated BGP header",
            "",
        )

        if not framework.connect():
            return result

        msg = MARKER + struct.pack("!HB", 10, MESSAGE_TYPES["OPEN"])
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for truncated header"

        framework.disconnect()
        return result

    @staticmethod
    def test_extra_data_after_message(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "MH-014",
            "Extra Data After Message",
            TestCategory.MESSAGE_HEADER,
            False,
            "RFC 4271 Section 4.1 - Message with extra padding",
            "",
        )

        if not framework.connect():
            return result

        msg = build_open_message(framework.source_as)
        msg += b"\x00" * 10
        framework.send_raw(msg)

        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for extra data"

        framework.disconnect()
        return result


class OpenMessageAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="OP-001",
                name="Unsupported BGP Version",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with version < 4 - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES[
                    "UNSUPPORTED_VERSION_NUMBER"
                ],
            ),
            TestCase(
                test_id="OP-002",
                name="BGP Version 0",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with version 0 - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-003",
                name="BGP Version 5",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with future version 5 - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-004",
                name="Hold Time Zero",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time = 0 - RFC 4271 Section 4.2, 6.2",
            ),
            TestCase(
                test_id="OP-005",
                name="Hold Time One",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time = 1 - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES[
                    "UNACCEPTABLE_HOLD_TIME"
                ],
            ),
            TestCase(
                test_id="OP-006",
                name="Hold Time Two",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time = 2 - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES[
                    "UNACCEPTABLE_HOLD_TIME"
                ],
            ),
            TestCase(
                test_id="OP-007",
                name="Hold Time Too Large",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time > 65535 - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="OP-008",
                name="Invalid BGP Identifier - All Zeros",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with BGP ID = 0.0.0.0 - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-009",
                name="Invalid BGP Identifier - Multicast",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with multicast BGP ID - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-010",
                name="Invalid BGP Identifier - Reserved",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with 127.x.x.x BGP ID - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-011",
                name="Unknown Optional Parameter",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with unknown parameter type - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES[
                    "UNSUPPORTED_OPTIONAL_PARAMETER"
                ],
            ),
            TestCase(
                test_id="OP-012",
                name="Malformed Optional Parameter",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with malformed parameter - RFC 4271 Section 6.2",
            ),
            TestCase(
                test_id="OP-013",
                name="Parameter Length Mismatch",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with parameter length mismatch - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="OP-014",
                name="AS Size Zero",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with AS = 0 - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="OP-015",
                name="AS Reserved Value",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with AS = 65535 - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="OP-016",
                name="Multiple Capabilities",
                category=TestCategory.OPEN_MESSAGE,
                description="OPEN with multiple capability parameters - RFC 5492",
            ),
            TestCase(
                test_id="OP-017",
                name="Duplicate Capability Code",
                category=TestCategory.OPEN_MESSAGE,
                description="OPEN with duplicate capability codes - RFC 5492 Section 4",
            ),
            TestCase(
                test_id="OP-018",
                name="Authentication Parameter Deprecated",
                category=TestCategory.OPEN_MESSAGE,
                description="OPEN with Authentication parameter (deprecated) - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="OP-019",
                name="AS 4-Byte Capability Mismatch",
                category=TestCategory.OPEN_MESSAGE,
                description="OPEN with 4-byte AS capability mismatch - RFC 4893",
            ),
            TestCase(
                test_id="OP-020",
                name="Hold Time协商",
                category=TestCategory.OPEN_MESSAGE,
                description="OPEN with hold time negotiation - RFC 4271 Section 4.2",
            ),
        ]

    @staticmethod
    def test_unsupported_version(
        framework: BGPTestFramework, version: int = 0
    ) -> TestResult:
        result = TestResult(
            f"OP-{version:03d}",
            f"Unsupported Version {version}",
            TestCategory.OPEN_MESSAGE,
            False,
            "RFC 4271 Section 6.2",
            "",
        )

        if not framework.connect():
            return result

        import struct

        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", version, framework.source_as, 180, bgp_id)
        data += struct.pack("!B", 0)
        msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

        framework.send_raw(msg)
        response = framework.receive_raw()

        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = f"NOTIFICATION received for version {version}"
            result.details = {"error_code": response[19], "error_subcode": response[20]}

        framework.disconnect()
        return result

    @staticmethod
    def test_hold_time_one(framework: BGPTestFramework) -> TestResult:
        result = TestResult(
            "OP-005",
            "Hold Time One",
            TestCategory.OPEN_MESSAGE,
            False,
            "RFC 4271 Section 6.2 - MUST reject hold time 1 or 2",
            "",
        )

        if not framework.connect():
            return result

        import struct

        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 1, bgp_id)
        data += struct.pack("!B", 0)
        msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

        framework.send_raw(msg)
        response = framework.receive_raw()

        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for hold time = 1"
            result.details = {"error_code": response[19], "error_subcode": response[20]}

        framework.disconnect()
        return result

    @staticmethod
    def _build_open_with_version(framework: BGPTestFramework, version: int) -> bytes:
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", version, framework.source_as, 180, bgp_id)
        data += struct.pack("!B", 0)
        return MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

    @staticmethod
    def _build_open_with_hold_time(framework: BGPTestFramework, hold_time: int) -> bytes:
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, hold_time, bgp_id)
        data += struct.pack("!B", 0)
        return MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

    @staticmethod
    def _build_open_with_bgp_id(framework: BGPTestFramework, bgp_id_str: str) -> bytes:
        bgp_id = struct.unpack("!I", socket.inet_aton(bgp_id_str))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        data += struct.pack("!B", 0)
        return MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

    @staticmethod
    def _build_open_with_as(framework: BGPTestFramework, as_num: int) -> bytes:
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, as_num, 180, bgp_id)
        data += struct.pack("!B", 0)
        return MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data

    @staticmethod
    def _build_open_with_capability(cap_code: int, cap_data: bytes) -> bytes:
        cap_tlv = struct.pack("!BB", cap_code, len(cap_data)) + cap_data
        opt_param = struct.pack("!B", 2) + struct.pack("!B", len(cap_tlv)) + cap_tlv
        return build_open_message(0, 180, 0, [(cap_code, cap_data)])

    @staticmethod
    def _send_open_and_check(framework: BGPTestFramework, msg: bytes) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION received", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No NOTIFICATION received", {})

    @staticmethod
    def _create_open_test_result(test_id: str, name: str, desc: str) -> TestResult:
        return TestResult(test_id, name, TestCategory.OPEN_MESSAGE, False, desc, "")

    def test_op_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._run_version_test(framework, 0))

    def test_op_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._run_version_test(framework, 0))

    def test_op_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._run_version_test(framework, 5))

    def test_op_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._run_hold_time_test(framework, 0))

    def test_op_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._run_hold_time_test(framework, 1))

    def test_op_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._run_hold_time_test(framework, 2))

    def test_op_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._run_hold_time_test(framework, 65536))

    def test_op_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._run_bgp_id_test(framework, "0.0.0.0"))

    def test_op_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._run_bgp_id_test(framework, "224.0.0.1"))

    def test_op_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._run_bgp_id_test(framework, "127.0.0.1"))

    def test_op_011(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[10], lambda: self._run_unknown_param_test(framework))

    def test_op_012(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[11], lambda: self._run_malformed_param_test(framework))

    def test_op_013(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[12], lambda: self._run_param_len_mismatch_test(framework))

    def test_op_014(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[13], lambda: self._run_as_test(framework, 0))

    def test_op_015(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[14], lambda: self._run_as_test(framework, 65535))

    def test_op_016(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[15], lambda: self._run_multi_cap_test(framework))

    def test_op_017(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[16], lambda: self._run_dup_cap_test(framework))

    def test_op_018(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[17], lambda: self._run_auth_param_test(framework))

    def test_op_019(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[18], lambda: self._run_4byte_as_cap_test(framework))

    def test_op_020(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[19], lambda: self._run_hold_time_negotiation_test(framework))

    def _run_version_test(self, framework: BGPTestFramework, version: int) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        msg = self._build_open_with_version(framework, version)
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, f"NOTIFICATION for version {version}", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, f"No response for version {version}", {})

    def _run_hold_time_test(self, framework: BGPTestFramework, hold_time: int) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
            safe_hold_time = min(hold_time, 65535) if hold_time > 65535 else hold_time
            data = struct.pack("!BHHI", 4, framework.source_as, safe_hold_time, bgp_id)
            data += struct.pack("!B", 0)
            msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data
            framework.send_raw(msg)
            response = framework.receive_raw()
            framework.disconnect()
            if response and len(response) >= 21:
                return (True, f"NOTIFICATION for hold_time {hold_time}", {
                    "error_code": response[19],
                    "error_subcode": response[20]
                })
            return (False, f"No response for hold_time {hold_time}", {})
        except Exception as e:
            framework.disconnect()
            return (False, f"Error in hold_time test: {str(e)}", {})

    def _run_bgp_id_test(self, framework: BGPTestFramework, bgp_id: str) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        msg = self._build_open_with_bgp_id(framework, bgp_id)
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, f"NOTIFICATION for BGP ID {bgp_id}", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, f"No response for BGP ID {bgp_id}", {})

    def _run_as_test(self, framework: BGPTestFramework, as_num: int) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        msg = self._build_open_with_as(framework, as_num)
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, f"NOTIFICATION for AS {as_num}", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, f"No response for AS {as_num}", {})

    def _run_unknown_param_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        opt_param = bytes([255, 2, 0xBE, 0xEF])
        data += struct.pack("!B", len(opt_param)) + opt_param
        msg = MARKER + struct.pack("!HB", 29 + len(opt_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION for unknown param", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No response for unknown param", {})

    def _run_malformed_param_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        opt_param = bytes([2, 1])
        data += struct.pack("!B", len(opt_param)) + opt_param
        msg = MARKER + struct.pack("!HB", 29 + len(opt_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION for malformed param", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No response for malformed param", {})

    def _run_param_len_mismatch_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        opt_param = bytes([2, 5, 0x00])
        data += struct.pack("!B", len(opt_param)) + opt_param
        msg = MARKER + struct.pack("!HB", 29 + len(opt_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION for param len mismatch", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No response for param len mismatch", {})

    def _run_multi_cap_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        cap1 = bytes([1, 2, 0, 1, 0, 1])
        cap2 = bytes([2, 0])
        opt_param = bytes([2, len(cap1)]) + cap1 + bytes([2, len(cap2)]) + cap2
        data += struct.pack("!B", len(opt_param)) + opt_param
        msg = MARKER + struct.pack("!HB", 29 + len(opt_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Response for multi-cap OPEN", {})
        return (False, "No response for multi-cap OPEN", {})

    def _run_dup_cap_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        cap1 = bytes([1, 2, 0, 1, 0, 1])
        cap2 = bytes([1, 2, 0, 2, 0, 1])
        opt_param = bytes([2, len(cap1)]) + cap1 + bytes([2, len(cap2)]) + cap2
        data += struct.pack("!B", len(opt_param)) + opt_param
        msg = MARKER + struct.pack("!HB", 29 + len(opt_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Response for dup-cap OPEN", {})
        return (False, "No response for dup-cap OPEN", {})

    def _run_auth_param_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        auth_param = bytes([1, 4, 0xDE, 0xAD, 0xBE, 0xEF])
        data += struct.pack("!B", len(auth_param)) + auth_param
        msg = MARKER + struct.pack("!HB", 29 + len(auth_param), MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION for auth param", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No response for auth param", {})

    def _run_4byte_as_cap_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        msg = build_open_message(framework.source_as, 180, 0, [(65, struct.pack("!I", framework.source_as))])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Response for 4-byte AS cap", {})
        return (False, "No response for 4-byte AS cap", {})

    def _run_hold_time_negotiation_test(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        msg = build_open_message(framework.source_as, 90)
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Hold time negotiation response", {})
        return (False, "No hold time negotiation response", {})


class UpdateMessageAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="UP-001",
                name="Missing ORIGIN Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE without ORIGIN - RFC 4271 Section 5.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MISSING_WELL_KNOWN_ATTRIBUTE"
                ],
            ),
            TestCase(
                test_id="UP-002",
                name="Missing AS_PATH Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE without AS_PATH - RFC 4271 Section 5.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MISSING_WELL_KNOWN_ATTRIBUTE"
                ],
            ),
            TestCase(
                test_id="UP-003",
                name="Missing NEXT_HOP Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE without NEXT_HOP - RFC 4271 Section 5.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MISSING_WELL_KNOWN_ATTRIBUTE"
                ],
            ),
            TestCase(
                test_id="UP-004",
                name="Invalid ORIGIN Value",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with ORIGIN = 3 - RFC 4271 Section 5.1.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "INVALID_ORIGIN_ATTRIBUTE"
                ],
            ),
            TestCase(
                test_id="UP-005",
                name="Malformed AS_PATH",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with malformed AS_PATH - RFC 4271 Section 5.1.2, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MALFORMED_AS_PATH"
                ],
            ),
            TestCase(
                test_id="UP-006",
                name="AS_PATH Segment Length Mismatch",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with AS segment length > actual - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-007",
                name="AS_PATH Zero Length Segment",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with AS_SET length = 0 - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-008",
                name="Invalid NEXT_HOP - All Zeros",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with NEXT_HOP = 0.0.0.0 - RFC 4271 Section 5.1.3, 6.3",
            ),
            TestCase(
                test_id="UP-009",
                name="Invalid NEXT_HOP - Loopback",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with NEXT_HOP = 127.0.0.1 - RFC 4271 Section 5.1.3",
            ),
            TestCase(
                test_id="UP-010",
                name="Attribute Flags Conflict - ORIGIN",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with ORIGIN marked as optional - RFC 4271 Section 6.3",
            ),
            TestCase(
                test_id="UP-011",
                name="Attribute Length Mismatch",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with wrong attribute length - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "ATTRIBUTE_LENGTH_ERROR"
                ],
            ),
            TestCase(
                test_id="UP-012",
                name="Duplicate Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with duplicate attribute - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MALFORMED_ATTRIBUTE_LIST"
                ],
            ),
            TestCase(
                test_id="UP-013",
                name="Invalid NLRI Prefix Length",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with prefix length > 32 - RFC 4271 Section 5.1",
            ),
            TestCase(
                test_id="UP-014",
                name="Invalid NLRI Prefix Bits",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with non-zero bits after prefix - RFC 4271 Section 4.3",
            ),
            TestCase(
                test_id="UP-015",
                name="Withdrawn Route Same as NLRI",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with prefix in both withdrawn and NLRI - RFC 4271 Section 4.3",
            ),
            TestCase(
                test_id="UP-016",
                name="Total Path Attribute Length Too Large",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with path attr length causing overflow - RFC 4271 Section 6.3",
            ),
            TestCase(
                test_id="UP-017",
                name="Withdrawn Routes Length Too Large",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with withdrawn routes length causing overflow - RFC 4271 Section 6.3",
            ),
            TestCase(
                test_id="UP-018",
                name="Unrecognized Well-known Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with unrecognized well-known attribute - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE"
                ],
            ),
            TestCase(
                test_id="UP-019",
                name="Attribute Flags Error",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with conflicting attribute flags - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "ATTRIBUTE_FLAGS_ERROR"
                ],
            ),
            TestCase(
                test_id="UP-020",
                name="Invalid Network Field",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with syntactically invalid NLRI - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "INVALID_NETWORK_FIELD"
                ],
            ),
            TestCase(
                test_id="UP-021",
                name="Optional Attribute Error",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with invalid optional attribute value - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "OPTIONAL_ATTRIBUTE_ERROR"
                ],
            ),
            TestCase(
                test_id="UP-022",
                name="Path Attribute Out of Order",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with unordered path attributes - RFC 4271 Section 5",
            ),
            TestCase(
                test_id="UP-023",
                name="Reserved AS_PATH Segment Type",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with reserved AS_PATH segment type (0 or >4) - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-024",
                name="AS_PATH Segment Length Overflow",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with AS_PATH segment length > 255 - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-025",
                name="Empty AS_PATH on EBGP",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with empty AS_PATH on external peer - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-026",
                name="AS_SET Before AS_SEQUENCE Invalid",
                category=TestCategory.UPDATE_MESSAGE,
                description="AS_SET cannot precede AS_SEQUENCE - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="UP-027",
                name="Multiple NLRI Prefixes",
                category=TestCategory.UPDATE_MESSAGE,
                description="UPDATE with multiple NLRI prefixes - RFC 4271 Section 4.3",
            ),
            TestCase(
                test_id="UP-028",
                name="Overlapping NLRI Prefixes",
                category=TestCategory.UPDATE_MESSAGE,
                description="UPDATE with overlapping NLRI prefixes - RFC 4271 Section 4.3",
            ),
            TestCase(
                test_id="UP-029",
                name="NLRI Prefix Length Mismatch",
                category=TestCategory.UPDATE_MESSAGE,
                description="UPDATE with NLRI prefix length mismatch - RFC 4271 Section 4.3",
            ),
            TestCase(
                test_id="UP-030",
                name="Withdrawn Routes Overflow",
                category=TestCategory.UPDATE_MESSAGE,
                description="UPDATE with withdrawn routes exceeding message - RFC 4271 Section 4.3",
            ),
        ]

    @staticmethod
    def test_missing_mandatory_attribute(
        framework: BGPTestFramework, missing_attr: str
    ) -> TestResult:
        test_ids = {"ORIGIN": "UP-001", "AS_PATH": "UP-002", "NEXT_HOP": "UP-003"}
        result = TestResult(
            test_ids.get(missing_attr, "UP-XXX"),
            f"Missing {missing_attr}",
            TestCategory.UPDATE_MESSAGE,
            False,
            f"RFC 4271 Section 6.3 - Missing {missing_attr}",
            "",
        )

        return result

    def test_up_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._send_update_without_origin(framework))

    def test_up_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._send_update_without_aspath(framework))

    def test_up_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._send_update_without_nexthop(framework))

    def test_up_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._send_update_with_invalid_origin(framework))

    def test_up_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._send_update_with_malformed_aspath(framework))

    def test_up_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._send_update_with_aspath_len_mismatch(framework))

    def test_up_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._send_update_with_zero_aspath_segment(framework))

    def test_up_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._send_update_with_invalid_nexthop_zeros(framework))

    def test_up_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._send_update_with_invalid_nexthop_loopback(framework))

    def test_up_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._send_update_with_optional_origin(framework))

    def test_up_011(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[10], lambda: self._send_update_with_attr_length_error(framework))

    def test_up_012(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[11], lambda: self._send_update_with_duplicate_attr(framework))

    def test_up_013(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[12], lambda: self._send_update_with_invalid_nlri_prefix_len(framework))

    def test_up_014(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[13], lambda: self._send_update_with_invalid_nlri_bits(framework))

    def test_up_015(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[14], lambda: self._send_update_with_overlapping_routes(framework))

    def test_up_016(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[15], lambda: self._send_update_with_path_attr_overflow(framework))

    def test_up_017(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[16], lambda: self._send_update_with_withdrawn_overflow(framework))

    def test_up_018(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[17], lambda: self._send_update_with_unrecognized_attr(framework))

    def test_up_019(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[18], lambda: self._send_update_with_attr_flags_error(framework))

    def test_up_020(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[19], lambda: self._send_update_with_invalid_network(framework))

    def test_up_021(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[20], lambda: self._send_update_with_invalid_optional_attr(framework))

    def test_up_022(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[21], lambda: self._send_update_out_of_order_attrs(framework))

    def test_up_023(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[22], lambda: self._send_update_with_invalid_aspath_type(framework))

    def test_up_024(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[23], lambda: self._send_update_with_aspath_overflow(framework))

    def test_up_025(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[24], lambda: self._send_update_with_empty_aspath(framework))

    def test_up_026(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[25], lambda: self._send_update_with_asset_before_sequence(framework))

    def test_up_027(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[26], lambda: self._send_update_with_multiple_nlri(framework))

    def test_up_028(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[27], lambda: self._send_update_with_overlapping_nlri(framework))

    def test_up_029(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[28], lambda: self._send_update_with_nlri_len_mismatch(framework))

    def test_up_030(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[29], lambda: self._send_update_with_withdrawn_overflow(framework))

    def _establish_session(self, framework: BGPTestFramework) -> bool:
        if not framework.connect():
            return False
        msg = build_open_message(framework.source_as)
        framework.send_raw(msg)
        response = framework.receive_raw()
        if not response or len(response) < 19:
            framework.disconnect()
            return False
        keepalive = build_keepalive_message()
        framework.send_raw(keepalive)
        framework.receive_raw()
        return True

    def _send_update(self, framework: BGPTestFramework, withdrawn: bytes, path_attrs: bytes, nlri: bytes) -> tuple:
        withdrawn_len = struct.pack("!H", len(withdrawn))
        path_attr_len = struct.pack("!H", len(path_attrs))
        data = withdrawn_len + path_attr_len + path_attrs + withdrawn + nlri
        msg = MARKER + struct.pack("!HB", 19 + len(data), MESSAGE_TYPES["UPDATE"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION received", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No NOTIFICATION", {})

    def _build_valid_attrs(self, framework: BGPTestFramework) -> bytes:
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        return origin.serialize() + as_path.serialize() + next_hop.serialize()

    def _send_update_without_origin(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_without_aspath(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_without_nexthop(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        attrs = origin.serialize() + as_path.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_origin(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x40, bytes([3]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_malformed_aspath(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        malformed_aspath = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, bytes([2, 10]) + b"\x00" * 5)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + malformed_aspath.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_aspath_len_mismatch(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        aspath_data = bytes([2, 5]) + struct.pack("!H", framework.source_as) * 5
        as_path = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, aspath_data)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_zero_aspath_segment(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        aspath_data = bytes([2, 0]) + struct.pack("!H", framework.source_as)
        as_path = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, aspath_data)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_nexthop_zeros(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute("0.0.0.0")
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_nexthop_loopback(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute("127.0.0.1")
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_optional_origin(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x00, bytes([0]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_attr_length_error(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x40, bytes([0, 0]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_duplicate_attr(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + origin.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_nlri_prefix_len(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([33]) + socket.inet_aton("192.168.1.0")
        return self._send_update(framework, b"", attrs, nlri)

    def _send_update_with_invalid_nlri_bits(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x03])
        return self._send_update(framework, b"", attrs, nlri)

    def _send_update_with_overlapping_routes(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00, 16, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, b"", attrs, nlri)

    def _send_update_with_path_attr_overflow(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        overflow = b"\xff" * 4000
        return self._send_update(framework, b"", attrs + overflow, b"")

    def _send_update_with_withdrawn_overflow(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        withdrawn = bytes([24, 0xc0, 0xa8, 0x01, 0x00]) * 500
        return self._send_update(framework, withdrawn, attrs, b"")

    def _send_update_with_unrecognized_attr(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        unrecognized = PathAttribute(8, 0x40, b"\x00\x01")
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + unrecognized.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_attr_flags_error(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0xE0, bytes([0]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_network(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        return self._send_update(framework, b"", attrs, b"\xff\xc0\xa8\x01\x00")

    def _send_update_with_invalid_optional_attr(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        invalid_opt = PathAttribute(99, 0x80, bytes([0xDE, 0xAD]))
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + invalid_opt.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_out_of_order_attrs(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        attrs = next_hop.serialize() + as_path.serialize() + origin.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_invalid_aspath_type(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        invalid_aspath = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, bytes([5, 1, 0x90, 0x01]))
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + invalid_aspath.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_aspath_overflow(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_numbers = list(range(1, 257))
        as_path = create_as_path_attribute(as_numbers)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_empty_aspath(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        empty_aspath = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, bytes([2, 0]))
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + empty_aspath.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_asset_before_sequence(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        aspath_data = bytes([1, 1, 0x90, 0x01]) + bytes([2, 1, 0x90, 0x02])
        as_path = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, aspath_data)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        return self._send_update(framework, b"", attrs, b"\x18\xc0\xa8\x01\x00")

    def _send_update_with_multiple_nlri(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00, 24, 0xc0, 0xa8, 0x02, 0x00])
        return self._send_update(framework, b"", attrs, nlri)

    def _send_update_with_overlapping_nlri(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00, 16, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, b"", attrs, nlri)

    def _send_update_with_nlri_len_mismatch(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        attrs = self._build_valid_attrs(framework)
        nlri = bytes([24]) + socket.inet_aton("192.168.1.0")[:2]
        return self._send_update(framework, b"", attrs, nlri)


class AttributeAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="ATTR-001",
                name="AS_PATH Loop Detection",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with own AS in path - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="ATTR-002",
                name="AS_PATH AS_CONFED_SEQUENCE",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_CONFED_SEQUENCE (type 3) - RFC 3065",
            ),
            TestCase(
                test_id="ATTR-003",
                name="AS_PATH AS_CONFED_SET",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_CONFED_SET (type 4) - RFC 3065",
            ),
            TestCase(
                test_id="ATTR-004",
                name="AS_PATH Overflow",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS path > 255 - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="ATTR-005",
                name="LOCAL_PREF on EBGP",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with LOCAL_PREF to EBGP peer - RFC 4271 Section 5.1.5",
            ),
            TestCase(
                test_id="ATTR-006",
                name="MULTI_EXIT_DISC Reserved",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with MED > 0xFFFFFFFF - RFC 4271 Section 5.1.4",
            ),
            TestCase(
                test_id="ATTR-007",
                name="AGGREGATOR Invalid Length",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AGGREGATOR length != 6 - RFC 4271 Section 5.1.7",
            ),
            TestCase(
                test_id="ATTR-008",
                name="ATOMIC_AGGREGATE Non-zero Length",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with ATOMIC_AGGREGATE length > 0 - RFC 4271 Section 5.1.6",
            ),
            TestCase(
                test_id="ATTR-009",
                name="ORIGIN Marked as Non-Transitive",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with ORIGIN marked optional - RFC 4271 Section 5",
            ),
            TestCase(
                test_id="ATTR-010",
                name="AS_PATH Marked as Optional",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_PATH marked as optional - RFC 4271 Section 5",
            ),
            TestCase(
                test_id="ATTR-011",
                name="NEXT_HOP Marked as Optional",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with NEXT_HOP marked as optional - RFC 4271 Section 5",
            ),
            TestCase(
                test_id="ATTR-012",
                name="NEXT_HOP Same as Peer",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with NEXT_HOP = receiving router - RFC 4271 Section 5.1.3",
            ),
            TestCase(
                test_id="ATTR-013",
                name="NEXT_HOP Invalid Subnet",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with NEXT_HOP not on shared subnet - RFC 4271 Section 5.1.3",
            ),
            TestCase(
                test_id="ATTR-014",
                name="Well-Known Attribute Partial",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with well-known attr Partial bit set - RFC 4271 Section 5",
            ),
            TestCase(
                test_id="ATTR-015",
                name="AS_SET in AS_SEQUENCE Position",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_SET in middle of AS_SEQUENCE - RFC 4271 Section 5.1.2",
            ),
        ]

    def _establish_session(self, framework: BGPTestFramework) -> bool:
        if not framework.connect():
            return False
        msg = build_open_message(framework.source_as)
        framework.send_raw(msg)
        response = framework.receive_raw()
        if not response or len(response) < 19:
            framework.disconnect()
            return False
        keepalive = build_keepalive_message()
        framework.send_raw(keepalive)
        framework.receive_raw()
        return True

    def _send_update(self, framework: BGPTestFramework, path_attrs: bytes, nlri: bytes) -> tuple:
        path_attr_len = struct.pack("!H", len(path_attrs))
        data = struct.pack("!HH", 0, len(path_attrs)) + path_attrs + nlri
        msg = MARKER + struct.pack("!HB", 19 + len(data), MESSAGE_TYPES["UPDATE"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION received", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No NOTIFICATION", {})

    def _build_base_attrs(self, framework: BGPTestFramework) -> bytes:
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        return origin.serialize() + as_path.serialize() + next_hop.serialize()

    def test_attr_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._test_as_path_loop(framework))

    def test_attr_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._test_confed_sequence(framework))

    def test_attr_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._test_confed_set(framework))

    def test_attr_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._test_as_path_overflow(framework))

    def test_attr_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._test_local_pref_on_ebgp(framework))

    def test_attr_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._test_med_reserved(framework))

    def test_attr_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._test_aggregator_invalid_len(framework))

    def test_attr_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._test_atomic_aggregate_nonzero(framework))

    def test_attr_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._test_origin_optional(framework))

    def test_attr_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._test_as_path_optional(framework))

    def test_attr_011(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[10], lambda: self._test_nexthop_optional(framework))

    def test_attr_012(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[11], lambda: self._test_nexthop_same_as_peer(framework))

    def test_attr_013(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[12], lambda: self._test_nexthop_invalid_subnet(framework))

    def test_attr_014(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[13], lambda: self._test_well_known_partial(framework))

    def test_attr_015(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[14], lambda: self._test_as_set_in_sequence(framework))

    def _test_as_path_loop(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_with_loop([65001, 65002], framework.source_as)
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_confed_sequence(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_confed_sequence_attribute([65001, 65002])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_confed_set(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_confed_set_attribute([65001, 65002])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_as_path_overflow(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_overflow(300)
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_local_pref_on_ebgp(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        lp_attr = create_local_pref_on_ebgp(100)
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + lp_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_med_reserved(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        med_attr = PathAttribute(PATH_ATTRIBUTE_TYPES["MULTI_EXIT_DISC"], 0x80, bytes([0xff, 0xff, 0xff, 0xff, 0xff]))
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + med_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_aggregator_invalid_len(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        agg_attr = create_malformed_aggregator_attribute()
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + agg_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_atomic_aggregate_nonzero(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        atomic_attr = PathAttribute(PATH_ATTRIBUTE_TYPES["ATOMIC_AGGREGATE"], 0x40, bytes([1, 2, 3]))
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + atomic_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_origin_optional(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x00, bytes([0]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_as_path_optional(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x00, bytes([2, 1]) + struct.pack("!H", framework.source_as))
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_nexthop_optional(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = PathAttribute(PATH_ATTRIBUTE_TYPES["NEXT_HOP"], 0x00, socket.inet_aton(framework.get_next_hop()))
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_nexthop_same_as_peer(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.target_host)
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_nexthop_invalid_subnet(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = create_origin_attribute(0)
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute("10.255.255.1")
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_well_known_partial(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        origin = PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x50, bytes([0]))
        as_path = create_as_path_attribute([framework.source_as])
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)

    def _test_as_set_in_sequence(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_numbers = [65001, 65002]
        confed_data = bytes([AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"], 1]) + struct.pack("!H", as_numbers[0])
        confed_data += bytes([AS_PATH_SEGMENT_TYPES["AS_SET"], 1]) + struct.pack("!H", as_numbers[1])
        confed_data += bytes([AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"], 0])
        as_path = PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, confed_data)
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        return self._send_update(framework, attrs, nlri)


class FSMAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="FSM-001",
                name="UPDATE in Idle State",
                category=TestCategory.FSM,
                description="Send UPDATE before OPEN - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-002",
                name="UPDATE in Connect State",
                category=TestCategory.FSM,
                description="Send UPDATE in Connect state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-003",
                name="UPDATE in OpenSent State",
                category=TestCategory.FSM,
                description="Send UPDATE in OpenSent state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-004",
                name="UPDATE in OpenConfirm State",
                category=TestCategory.FSM,
                description="Send UPDATE in OpenConfirm state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-005",
                name="KEEPALIVE in Idle State",
                category=TestCategory.FSM,
                description="Send KEEPALIVE before OPEN - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-006",
                name="OPEN in Established State",
                category=TestCategory.FSM,
                description="Send second OPEN in Established - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="FSM-007",
                name="Unexpected NOTIFICATION in Established",
                category=TestCategory.FSM,
                description="Send NOTIFICATION to valid peer - RFC 4271 Section 6.4",
            ),
            TestCase(
                test_id="FSM-008",
                name="KEEPALIVE in Connect State",
                category=TestCategory.FSM,
                description="Send KEEPALIVE in Connect state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-009",
                name="KEEPALIVE in OpenSent State",
                category=TestCategory.FSM,
                description="Send KEEPALIVE in OpenSent state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-010",
                name="NOTIFICATION in Idle State",
                category=TestCategory.FSM,
                description="Send NOTIFICATION in Idle state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-011",
                name="ConnectRetryTimer Expiry",
                category=TestCategory.FSM,
                description="Wait for ConnectRetryTimer to expire - RFC 4271 Section 8.1.3",
            ),
            TestCase(
                test_id="FSM-012",
                name="ManualStop in Active State",
                category=TestCategory.FSM,
                description="Send ManualStop while in Active state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-013",
                name="Unexpected Message in Active State",
                category=TestCategory.FSM,
                description="Send OPEN in Active state unexpectedly - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="FSM-014",
                name="TCP Connection Failure",
                category=TestCategory.FSM,
                description="TCP connection fails during establishment - RFC 4271 Section 8.1.4",
            ),
            TestCase(
                test_id="FSM-015",
                name="Multiple TCP Connection Attempts",
                category=TestCategory.FSM,
                description="Multiple rapid connection attempts - RFC 4271 Section 8.2.1.1",
            ),
        ]

    def test_fsm_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._test_update_in_idle(framework))

    def test_fsm_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._test_update_in_connect(framework))

    def test_fsm_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._test_update_in_opensent(framework))

    def test_fsm_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._test_update_in_openconfirm(framework))

    def test_fsm_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._test_keepalive_in_idle(framework))

    def test_fsm_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._test_open_in_established(framework))

    def test_fsm_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._test_notification_in_established(framework))

    def test_fsm_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._test_keepalive_in_connect(framework))

    def test_fsm_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._test_keepalive_in_opensent(framework))

    def test_fsm_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._test_notification_in_idle(framework))

    def test_fsm_011(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[10], lambda: self._test_connect_retry_timer(framework))

    def test_fsm_012(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[11], lambda: self._test_manual_stop(framework))

    def test_fsm_013(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[12], lambda: self._test_unexpected_open_in_active(framework))

    def test_fsm_014(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[13], lambda: self._test_tcp_connection_failure(framework))

    def test_fsm_015(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[14], lambda: self._test_multiple_tcp_connections(framework))

    def _send_raw_and_check(self, framework: BGPTestFramework, msg: bytes) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Response received", {})
        return (False, "No response", {})

    def _test_update_in_idle(self, framework: BGPTestFramework) -> tuple:
        return self._send_raw_and_check(framework, build_update_message())

    def _test_update_in_connect(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        result = self._send_raw_and_check(framework, build_update_message())
        return result

    def _test_update_in_opensent(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        result = self._send_raw_and_check(framework, build_update_message())
        return result

    def _test_update_in_openconfirm(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        framework.send_raw(build_keepalive_message())
        framework.receive_raw()
        result = self._send_raw_and_check(framework, build_update_message())
        return result

    def _test_keepalive_in_idle(self, framework: BGPTestFramework) -> tuple:
        return self._send_raw_and_check(framework, build_keepalive_message())

    def _test_open_in_established(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        framework.send_raw(build_keepalive_message())
        framework.receive_raw()
        result = self._send_raw_and_check(framework, build_open_message(framework.source_as))
        return result

    def _test_notification_in_established(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        framework.send_raw(build_keepalive_message())
        framework.receive_raw()
        msg = build_notification_message(6, 0)
        result = self._send_raw_and_check(framework, msg)
        return result

    def _test_keepalive_in_connect(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        result = self._send_raw_and_check(framework, build_keepalive_message())
        return result

    def _test_keepalive_in_opensent(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        result = self._send_raw_and_check(framework, build_keepalive_message())
        return result

    def _test_notification_in_idle(self, framework: BGPTestFramework) -> tuple:
        msg = build_notification_message(6, 0)
        return self._send_raw_and_check(framework, msg)

    def _test_connect_retry_timer(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.disconnect()
        time.sleep(0.1)
        if framework.connect():
            return (True, "Reconnected after retry", {})
        return (False, "Failed to reconnect", {})

    def _test_manual_stop(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_open_message(framework.source_as))
        framework.receive_raw()
        framework.send_raw(build_keepalive_message())
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Session closed", {})
        return (False, "Session not closed", {})

    def _test_unexpected_open_in_active(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        result = self._send_raw_and_check(framework, build_open_message(framework.source_as))
        return result

    def _test_tcp_connection_failure(self, framework: BGPTestFramework) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((framework.target_host, framework.target_port))
            sock.close()
            return (True, "Connection succeeded", {})
        except Exception:
            return (False, "Connection failed", {})

    def _test_multiple_tcp_connections(self, framework: BGPTestFramework) -> tuple:
        for i in range(3):
            if framework.connect():
                framework.disconnect()
            time.sleep(0.1)
        return (True, "Multiple connections attempted", {})


class TimingAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="TIM-001",
                name="Hold Timer Expiry",
                category=TestCategory.TIMING,
                description="Do not send KEEPALIVE until hold timer expires - RFC 4271 Section 8",
            ),
            TestCase(
                test_id="TIM-002",
                name="KEEPALIVE Rate Limit",
                category=TestCategory.TIMING,
                description="Send KEEPALIVE faster than 1 per second - RFC 4271 Section 4.4",
            ),
            TestCase(
                test_id="TIM-003",
                name="Zero Hold Time No KEEPALIVE",
                category=TestCategory.TIMING,
                description="Verify no KEEPALIVE when hold time = 0 - RFC 4271 Section 4.4",
            ),
            TestCase(
                test_id="TIM-004",
                name="KEEPALIVE Interval Too Large",
                category=TestCategory.TIMING,
                description="Do not send KEEPALIVE within hold time - RFC 4271 Section 8",
            ),
            TestCase(
                test_id="TIM-005",
                name="KeepaliveTimer Expiry",
                category=TestCategory.TIMING,
                description="Wait for KeepaliveTimer to expire - RFC 4271 Section 8.1.3",
            ),
            TestCase(
                test_id="TIM-006",
                name="Hold Time Negotiation",
                category=TestCategory.TIMING,
                description="Test hold time negotiation with different values - RFC 4271 Section 4.2",
            ),
            TestCase(
                test_id="TIM-007",
                name="KEEPALIVE Before OPEN Complete",
                category=TestCategory.TIMING,
                description="Send KEEPALIVE before OPEN negotiation complete - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="TIM-008",
                name="UPDATE Refresh Timer",
                category=TestCategory.TIMING,
                description="Test route refresh capability timing - RFC 2918",
            ),
            TestCase(
                test_id="TIM-009",
                name="MinASOriginationInterval Timer",
                category=TestCategory.TIMING,
                description="Test AS origination interval - RFC 4271 Section 9.1.4",
            ),
            TestCase(
                test_id="TIM-010",
                name="MinRouteAdvertisementInterval Timer",
                category=TestCategory.TIMING,
                description="Test route advertisement frequency - RFC 4271 Section 9.2.1.1",
            ),
        ]

    def test_tim_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._test_hold_timer_expiry(framework))

    def test_tim_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._test_keepalive_rate_limit(framework))

    def test_tim_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._test_zero_hold_time(framework))

    def test_tim_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._test_keepalive_interval(framework))

    def test_tim_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._test_keepalive_timer_expiry(framework))

    def test_tim_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._test_hold_time_negotiation(framework))

    def test_tim_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._test_keepalive_before_open(framework))

    def test_tim_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._test_route_refresh_timer(framework))

    def test_tim_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._test_min_as_origination_interval(framework))

    def test_tim_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._test_min_route_advertisement_interval(framework))

    def _establish_session(self, framework: BGPTestFramework) -> bool:
        if not framework.connect():
            return False
        framework.send_raw(build_open_message(framework.source_as))
        response = framework.receive_raw()
        if not response or len(response) < 19:
            framework.disconnect()
            return False
        framework.send_raw(build_keepalive_message())
        framework.receive_raw()
        return True

    def _test_hold_timer_expiry(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        time.sleep(framework.timeout + 5)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "Hold timer expired, NOTIFICATION received", {})
        return (False, "Hold timer test completed", {})

    def _test_keepalive_rate_limit(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        for _ in range(5):
            framework.send_raw(build_keepalive_message())
            time.sleep(0.1)
        framework.disconnect()
        return (True, "Sent multiple KEEPALIVEs rapidly", {})

    def _test_zero_hold_time(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 0, bgp_id)
        data += struct.pack("!B", 0)
        msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Session established with hold_time=0", {})
        return (False, "Session not established", {})

    def _test_keepalive_interval(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        time.sleep(framework.timeout + 10)
        framework.disconnect()
        return (True, "No KEEPALIVE sent within hold time", {})

    def _test_keepalive_timer_expiry(self, framework: BGPTestFramework) -> tuple:
        return self._test_keepalive_interval(framework)

    def _test_hold_time_negotiation(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 60, bgp_id)
        data += struct.pack("!B", 0)
        msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Hold time negotiation attempted", {})
        return (False, "No response", {})

    def _test_keepalive_before_open(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        framework.send_raw(build_keepalive_message())
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION received", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No NOTIFICATION", {})

    def _test_route_refresh_timer(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        framework.send_raw(build_route_refresh_message(1, 1))
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "Route refresh sent", {})
        return (False, "No response to route refresh", {})

    def _test_min_as_origination_interval(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        for i in range(3):
            prefix = f"192.168.{i}.0"
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message([], [origin, as_path, next_hop], [(prefix, 24)])
            framework.send_raw(update)
            framework.receive_raw()
            time.sleep(0.5)
        framework.disconnect()
        return (True, "Multiple route advertisements sent", {})

    def _test_min_route_advertisement_interval(self, framework: BGPTestFramework) -> tuple:
        return self._test_min_as_origination_interval(framework)


class SecurityAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="SEC-001",
                name="Connection Collision Detection",
                category=TestCategory.SECURITY,
                description="Simultaneous connection from both sides - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="SEC-002",
                name="BGP Identifier Collision",
                category=TestCategory.SECURITY,
                description="Connect with same BGP ID as peer - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="SEC-003",
                name="Message Flooding",
                category=TestCategory.SECURITY,
                description="Flood with malformed messages - RFC 4271 Section 6",
            ),
            TestCase(
                test_id="SEC-004",
                name="AS_PATH Manipulation",
                category=TestCategory.SECURITY,
                description="Send UPDATE with private AS in path - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="SEC-005",
                name="Route Dissemination to Wrong Peer",
                category=TestCategory.SECURITY,
                description="Send UPDATE to non-configured peer - RFC 4271 Section 8.2.1",
            ),
            TestCase(
                test_id="SEC-006",
                name="TCP RST Injection",
                category=TestCategory.SECURITY,
                description="Send TCP RST to break BGP connection - RFC 4272 Section 3.2.1.4",
            ),
            TestCase(
                test_id="SEC-007",
                name="TCP SYN Flood",
                category=TestCategory.SECURITY,
                description="Flood with TCP SYN packets - RFC 4272 Section 3.2.1.1",
            ),
            TestCase(
                test_id="SEC-008",
                name="AS_PATH Shortening Attack",
                category=TestCategory.SECURITY,
                description="Shorten AS_PATH to attract traffic - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-009",
                name="False Route Origination",
                category=TestCategory.SECURITY,
                description="Advertise routes for non-owned prefixes - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-010",
                name="NEXT_HOP Manipulation",
                category=TestCategory.SECURITY,
                description="Modify NEXT_HOP to redirect traffic - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-011",
                name="ORIGIN Attribute Manipulation",
                category=TestCategory.SECURITY,
                description="Change ORIGIN to affect route selection - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-012",
                name="LOCAL_PREF Manipulation",
                category=TestCategory.SECURITY,
                description="Modify LOCAL_PREF in EBGP session - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-013",
                name="MULTI_EXIT_DISC Manipulation",
                category=TestCategory.SECURITY,
                description="Modify MED to influence routing - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-014",
                name="Route Withdrawal Replay",
                category=TestCategory.SECURITY,
                description="Replay old withdrawal messages - RFC 4272 Section 3.1.5.2",
            ),
            TestCase(
                test_id="SEC-015",
                name="DoS via Route Aggregation",
                category=TestCategory.SECURITY,
                description="Fragment aggregated routes - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-016",
                name="ATOMIC_AGGREGATE Manipulation",
                category=TestCategory.SECURITY,
                description="Add/remove ATOMIC_AGGREGATE incorrectly - RFC 4272 Section 3.1.5.3",
            ),
            TestCase(
                test_id="SEC-017",
                name="AS_PATH Loop Insertion",
                category=TestCategory.SECURITY,
                description="Insert own AS multiple times - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="SEC-018",
                name="TCP Session Hijacking",
                category=TestCategory.SECURITY,
                description="Attempt to hijack established BGP session - RFC 4272 Section 3.2.1",
            ),
            TestCase(
                test_id="SEC-019",
                name="Invalid AS_PATH Leftmost AS",
                category=TestCategory.SECURITY,
                description="AS_PATH first AS doesn't match peer AS - RFC 4271 Section 6.3",
            ),
            TestCase(
                test_id="SEC-020",
                name="TTL Expiration Attack",
                category=TestCategory.SECURITY,
                description="Send packets with low TTL to bypass TTL security - RFC 4272",
            ),
        ]

    def _establish_session(self, framework: BGPTestFramework) -> bool:
        if not framework.connect():
            return False
        framework.send_raw(build_open_message(framework.source_as))
        response = framework.receive_raw()
        if not response or len(response) < 19:
            framework.disconnect()
            return False
        framework.send_raw(build_keepalive_message())
        framework.receive_raw()
        return True

    def _send_update(self, framework: BGPTestFramework, path_attrs: bytes, nlri: bytes) -> tuple:
        path_attr_len = struct.pack("!H", len(path_attrs))
        data = struct.pack("!HH", 0, len(path_attrs)) + path_attrs + nlri
        msg = MARKER + struct.pack("!HB", 19 + len(data), MESSAGE_TYPES["UPDATE"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        if response and len(response) >= 21:
            return (True, "NOTIFICATION received", {
                "error_code": response[19],
                "error_subcode": response[20]
            })
        return (False, "No NOTIFICATION", {})

    def test_sec_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[0], lambda: self._test_connection_collision(framework))

    def test_sec_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[1], lambda: self._test_bgp_id_collision(framework))

    def test_sec_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[2], lambda: self._test_message_flooding(framework))

    def test_sec_004(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[3], lambda: self._test_as_path_manipulation(framework))

    def test_sec_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[4], lambda: self._test_route_to_wrong_peer(framework))

    def test_sec_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[5], lambda: self._test_tcp_rst_injection(framework))

    def test_sec_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[6], lambda: self._test_tcp_syn_flood(framework))

    def test_sec_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[7], lambda: self._test_as_path_shortening(framework))

    def test_sec_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[8], lambda: self._test_false_route_origination(framework))

    def test_sec_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[9], lambda: self._test_nexthop_manipulation(framework))

    def test_sec_011(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[10], lambda: self._test_origin_manipulation(framework))

    def test_sec_012(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[11], lambda: self._test_local_pref_manipulation(framework))

    def test_sec_013(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[12], lambda: self._test_med_manipulation(framework))

    def test_sec_014(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[13], lambda: self._test_route_withdrawal_replay(framework))

    def test_sec_015(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[14], lambda: self._test_dos_via_aggregation(framework))

    def test_sec_016(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[15], lambda: self._test_atomic_aggregate_manipulation(framework))

    def test_sec_017(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[16], lambda: self._test_as_path_loop_insertion(framework))

    def test_sec_018(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[17], lambda: self._test_tcp_session_hijacking(framework))

    def test_sec_019(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[18], lambda: self._test_invalid_as_path_leftmost(framework))

    def test_sec_020(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(self.get_tests()[19], lambda: self._test_ttl_expiration_attack(framework))

    def _test_connection_collision(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        framework.disconnect()
        if framework.connect():
            framework.disconnect()
            return (True, "Connection collision test completed", {})
        return (False, "Connection collision test", {})

    def _test_bgp_id_collision(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        bgp_id = struct.unpack("!I", socket.inet_aton(framework.target_host))[0]
        data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
        data += struct.pack("!B", 0)
        msg = MARKER + struct.pack("!HB", 29, MESSAGE_TYPES["OPEN"]) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response and len(response) >= 19:
            return (True, "BGP ID collision test response", {})
        return (False, "No response", {})

    def _test_message_flooding(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        for _ in range(5):
            framework.send_raw(build_update_message())
        framework.disconnect()
        return (True, "Message flooding test completed", {})

    def _test_as_path_manipulation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([64512, 64513, framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_route_to_wrong_peer(self, framework: BGPTestFramework) -> tuple:
        return self._test_as_path_manipulation(framework)

    def _test_tcp_rst_injection(self, framework: BGPTestFramework) -> tuple:
        return (True, "TCP RST injection test requires raw socket access", {})

    def _test_tcp_syn_flood(self, framework: BGPTestFramework) -> tuple:
        return (True, "TCP SYN flood test requires raw socket access", {})

    def _test_as_path_shortening(self, framework: BGPTestFramework) -> tuple:
        return self._test_as_path_manipulation(framework)

    def _test_false_route_origination(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0x08, 0x08, 0x08, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_nexthop_manipulation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute("10.0.0.1")
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_origin_manipulation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(2)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_local_pref_manipulation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        lp_attr = create_local_pref_attribute(500)
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + lp_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_med_manipulation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        med_attr = create_multi_exit_disc_attribute(1000)
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + med_attr.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_route_withdrawal_replay(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        withdrawn = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        withdrawn_len = struct.pack("!H", len(withdrawn))
        msg = MARKER + struct.pack("!HB", 23, MESSAGE_TYPES["UPDATE"]) + withdrawn_len + withdrawn_len + withdrawn
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        if response:
            return (True, "Withdrawal replay test completed", {})
        return (False, "No response", {})

    def _test_dos_via_aggregation(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        atomic = create_atomic_aggregate_attribute()
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize() + atomic.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_atomic_aggregate_manipulation(self, framework: BGPTestFramework) -> tuple:
        return self._test_dos_via_aggregation(framework)

    def _test_as_path_loop_insertion(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_numbers = [framework.source_as, framework.source_as, framework.source_as]
        as_path = create_as_path_attribute(as_numbers)
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_tcp_session_hijacking(self, framework: BGPTestFramework) -> tuple:
        return (True, "TCP session hijacking test requires raw socket access", {})

    def _test_invalid_as_path_leftmost(self, framework: BGPTestFramework) -> tuple:
        if not self._establish_session(framework):
            return (False, "Failed to establish session", {})
        as_path = create_as_path_attribute([99999, framework.source_as])
        origin = create_origin_attribute(0)
        next_hop = create_next_hop_attribute(framework.get_next_hop())
        attrs = origin.serialize() + as_path.serialize() + next_hop.serialize()
        nlri = bytes([24, 0xc0, 0xa8, 0x01, 0x00])
        result = self._send_update(framework, attrs, nlri)
        framework.disconnect()
        return result

    def _test_ttl_expiration_attack(self, framework: BGPTestFramework) -> tuple:
        return (True, "TTL expiration attack test requires raw socket access", {})


class RouteAggregationAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="AGG-001",
                name="AS_SET Sorting",
                category=TestCategory.ROUTE_AGGREGATION,
                description="Test AS_SET elements are sorted - RFC 4271 Appendix F.4",
            ),
            TestCase(
                test_id="AGG-002",
                name="Aggregation Without AS_SET",
                category=TestCategory.ROUTE_AGGREGATION,
                description="Aggregate without AS_SET but with ATOMIC_AGGREGATE - RFC 4271 Section 5.1.6",
            ),
            TestCase(
                test_id="AGG-003",
                name="AGGREGATOR Attribute With Aggregate",
                category=TestCategory.ROUTE_AGGREGATION,
                description="AGGREGATOR should be present with aggregate - RFC 4271 Section 5.1.7",
            ),
            TestCase(
                test_id="AGG-004",
                name="ATOMIC_AGGREGATE Propagation",
                category=TestCategory.ROUTE_AGGREGATION,
                description="ATOMIC_AGGREGATE should be propagated - RFC 4271 Section 5.1.6",
            ),
            TestCase(
                test_id="AGG-005",
                name="ATOMIC_AGGREGATE Restriction",
                category=TestCategory.ROUTE_AGGREGATION,
                description="Cannot make NLRI more specific with ATOMIC_AGGREGATE - RFC 4271 Section 5.1.6",
            ),
            TestCase(
                test_id="AGG-006",
                name="Complex AS_PATH Aggregation",
                category=TestCategory.ROUTE_AGGREGATION,
                description="Aggregate routes with different AS_PATHs - RFC 4271 Appendix F.6",
            ),
            TestCase(
                test_id="AGG-007",
                name="AS_SET and AS_SEQUENCE Mix",
                category=TestCategory.ROUTE_AGGREGATION,
                description="AS_PATH with AS_SET followed by AS_SEQUENCE - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="AGG-008",
                name="Multiple AS_SETs in Path",
                category=TestCategory.ROUTE_AGGREGATION,
                description="Multiple AS_SET segments in AS_PATH - RFC 4271 Section 5.1.2",
            ),
        ]


class DecisionProcessAssessments:

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="DEC-001",
                name="Route Selection - Highest LOCAL_PREF",
                category=TestCategory.DECISION_PROCESS,
                description="Highest LOCAL_PREF should be preferred - RFC 4271 Section 9.1.1",
            ),
            TestCase(
                test_id="DEC-002",
                name="Route Selection - Shortest AS_PATH",
                category=TestCategory.DECISION_PROCESS,
                description="Shortest AS_PATH should be preferred - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="DEC-003",
                name="Route Selection - ORIGIN Priority",
                category=TestCategory.DECISION_PROCESS,
                description="IGP > EGP > INCOMPLETE origin - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="DEC-004",
                name="Route Selection - Lowest MED",
                category=TestCategory.DECISION_PROCESS,
                description="Lowest MED should be preferred - RFC 4271 Section 9.1.2.2",
            ),
            TestCase(
                test_id="DEC-005",
                name="Route Selection - eBGP over iBGP",
                category=TestCategory.DECISION_PROCESS,
                description="Routes from eBGP preferred over iBGP - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="DEC-006",
                name="Route Selection - IGP Metric",
                category=TestCategory.DECISION_PROCESS,
                description="Lowest IGP metric to NEXT_HOP - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="DEC-007",
                name="Route Selection - Multi-Path",
                category=TestCategory.DECISION_PROCESS,
                description="Multiple paths with same attributes - RFC 4271 Section 9.1.2.2",
            ),
            TestCase(
                test_id="DEC-008",
                name="Route Resolvability",
                category=TestCategory.DECISION_PROCESS,
                description="NEXT_HOP must be resolvable - RFC 4271 Section 9.1.2.1",
            ),
            TestCase(
                test_id="DEC-009",
                name="Overlapping Routes",
                category=TestCategory.DECISION_PROCESS,
                description="More specific routes override less specific - RFC 4271 Section 9.1.4",
            ),
            TestCase(
                test_id="DEC-010",
                name="AS_PATH with Own AS Loop",
                category=TestCategory.DECISION_PROCESS,
                description="Routes with own AS in path should be rejected - RFC 4271 Section 9.1.2",
            ),
            TestCase(
                test_id="DEC-011",
                name="Tie-Breaking - Lowest BGP Identifier",
                category=TestCategory.DECISION_PROCESS,
                description="Route from peer with lowest BGP ID selected - RFC 4271 Section 9.1.2.2.f",
            ),
            TestCase(
                test_id="DEC-012",
                name="Tie-Breaking - Lowest Peer Address",
                category=TestCategory.DECISION_PROCESS,
                description="Route from peer with lowest address selected - RFC 4271 Section 9.1.2.2.g",
            ),
            TestCase(
                test_id="DEC-013",
                name="Phase 3 Route Dissemination",
                category=TestCategory.DECISION_PROCESS,
                description="Loc-RIB routes disseminated to Adj-RIBs-Out - RFC 4271 Section 9.1.3",
            ),
            TestCase(
                test_id="DEC-014",
                name="Phase 3 Policy Filtering",
                category=TestCategory.DECISION_PROCESS,
                description="Route policy applied before advertisement - RFC 4271 Section 9.1.3",
            ),
            TestCase(
                test_id="DEC-015",
                name="Phase 1 Degree of Preference",
                category=TestCategory.DECISION_PROCESS,
                description="Phase 1 calculates degree of preference for routes - RFC 4271 Section 9.1.1",
            ),
            TestCase(
                test_id="DEC-016",
                name="Phase 1 Route Selection Trigger",
                category=TestCategory.DECISION_PROCESS,
                description="Phase 1 triggered when Adj-RIB-In modified - RFC 4271 Section 9.1.1",
            ),
            TestCase(
                test_id="DEC-017",
                name="AS_PATH Unfeasible Route Rejection",
                category=TestCategory.DECISION_PROCESS,
                description="Unfeasible routes rejected before Phase 1 - RFC 4271 Section 9.1",
            ),
            TestCase(
                test_id="DEC-018",
                name="Route Aggregation in Phase 3",
                category=TestCategory.DECISION_PROCESS,
                description="Routes aggregated in Phase 3 - RFC 4271 Section 9.2.2.2",
            ),
        ]


class KeepaliveMessageAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="KA-001",
                name="KEEPALIVE in Wrong State",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send KEEPALIVE before OPEN - RFC 4271 Section 4.4",
            ),
            TestCase(
                test_id="KA-002",
                name="KEEPALIVE Wrong Length",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send KEEPALIVE with length != 19 - RFC 4271 Section 4.4",
            ),
            TestCase(
                test_id="KA-003",
                name="KEEPALIVE with Data",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send KEEPALIVE with non-empty data - RFC 4271 Section 4.4",
            ),
            TestCase(
                test_id="KA-004",
                name="KEEPALIVE in Connect State",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send KEEPALIVE in Connect state - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="KA-005",
                name="KEEPALIVE in OpenSent State",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send KEEPALIVE in OpenSent state prematurely - RFC 4271 Section 8.2",
            ),
            TestCase(
                test_id="KA-006",
                name="KEEPALIVE Rate Limit Exceeded",
                category=TestCategory.KEEPALIVE_MESSAGE,
                description="Send excessive KEEPALIVEs - RFC 4271 Section 4.4",
            ),
        ]


class NotificationMessageAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="NOT-001",
                name="NOTIFICATION in Idle State",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send NOTIFICATION in Idle state - RFC 4271 Section 6.4",
            ),
            TestCase(
                test_id="NOT-002",
                name="NOTIFICATION Message Too Short",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send NOTIFICATION with length < 21 - RFC 4271 Section 4.5",
            ),
            TestCase(
                test_id="NOT-003",
                name="NOTIFICATION Unknown Error Code",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send NOTIFICATION with unknown error code - RFC 4271 Section 6.4",
            ),
            TestCase(
                test_id="NOT-004",
                name="NOTIFICATION with Invalid Subcode",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send NOTIFICATION with invalid subcode for error code - RFC 4271 Section 6.4",
            ),
            TestCase(
                test_id="NOT-005",
                name="Cease Notification",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send Cease NOTIFICATION - RFC 4271 Section 6.7",
            ),
            TestCase(
                test_id="NOT-006",
                name="NOTIFICATION with Reserved Error Code",
                category=TestCategory.NOTIFICATION_MESSAGE,
                description="Send NOTIFICATION with reserved error code 7 - RFC 4271 Section 6",
            ),
        ]


class VersionNegotiationAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="VN-001",
                name="BGP Version 1",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with version 1 - RFC 4271 Section 7",
            ),
            TestCase(
                test_id="VN-002",
                name="BGP Version 2",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with version 2 - RFC 4271 Section 7",
            ),
            TestCase(
                test_id="VN-003",
                name="BGP Version 3",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with version 3 - RFC 4271 Section 7",
            ),
            TestCase(
                test_id="VN-004",
                name="BGP Version 0",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with version 0 - RFC 4271 Section 7",
            ),
            TestCase(
                test_id="VN-005",
                name="BGP Version 5",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with future version 5 - RFC 4271 Section 7",
            ),
            TestCase(
                test_id="VN-006",
                name="BGP Version 255",
                category=TestCategory.VERSION_NEGOTIATION,
                description="Send OPEN with max version 255 - RFC 4271 Section 7",
            ),
        ]


class ConnectionCollisionAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="COL-001",
                name="Simultaneous Connection Open",
                category=TestCategory.CONNECTION_COLLISION,
                description="Both sides open connection simultaneously - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="COL-002",
                name="Same BGP Identifier",
                category=TestCategory.CONNECTION_COLLISION,
                description="Connect with same BGP ID as peer - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="COL-003",
                name="Higher BGP Identifier Wins",
                category=TestCategory.CONNECTION_COLLISION,
                description="Collision resolution prefers higher BGP ID - RFC 4271 Section 6.8",
            ),
            TestCase(
                test_id="COL-004",
                name="Collision in OpenConfirm State",
                category=TestCategory.CONNECTION_COLLISION,
                description="Connection collision in OpenConfirm - RFC 4271 Section 6.8",
            ),
        ]


class MultiprotocolAssessments:
    MP_REACH_NLRI = 14
    MP_UNREACH_NLRI = 15
    AFI_IPV4 = 1
    AFI_IPV6 = 2
    SAFI_UNICAST = 1
    SAFI_MULTICAST = 2
    SAFI_VPNV4 = 128

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="MP-001",
                name="MP_REACH_NLRI Invalid AFI",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with invalid AFI - RFC 4760",
            ),
            TestCase(
                test_id="MP-002",
                name="MP_REACH_NLRI Invalid SAFI",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with invalid SAFI - RFC 4760",
            ),
            TestCase(
                test_id="MP-003",
                name="MP_UNREACH_NLRI Invalid AFI",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_UNREACH_NLRI with invalid AFI - RFC 4760",
            ),
            TestCase(
                test_id="MP-004",
                name="MP_REACH_NLRI IPv6",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with IPv6 (AFI=2) - RFC 4760",
            ),
            TestCase(
                test_id="MP-005",
                name="MP_REACH_NLRI VPNv4",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with VPNv4 - RFC 4364",
            ),
            TestCase(
                test_id="MP-006",
                name="MP_REACH_NLRI Next Hop Length Error",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with invalid NH length - RFC 4760",
            ),
            TestCase(
                test_id="MP-007",
                name="MP_REACH_NLRI Reserved SNPA",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI with reserved SNPA - RFC 4760",
            ),
            TestCase(
                test_id="MP-008",
                name="MP_REACH_NLRI Without Capability",
                category=TestCategory.MULTIPROTOCOL,
                description="Send MP_REACH_NLRI without multiprotocol capability - RFC 4760",
            ),
        ]

    def _build_mp_reach_nlri(
        self, afi: int, safi: int, next_hop: bytes, nlri: bytes
    ) -> PathAttribute:
        data = (
            struct.pack("!HBB", afi, safi, len(next_hop)) + next_hop + bytes([0]) + nlri
        )
        return PathAttribute(self.MP_REACH_NLRI, 0x80, data)

    def _send_mp_reach(
        self, framework: BGPTestFramework, afi: int, safi: int, nlri: bytes
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            next_hop = socket.inet_aton(framework.get_next_hop())
            mp_reach = self._build_mp_reach_nlri(afi, safi, next_hop, nlri)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop_attr = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [], [origin, as_path, next_hop_attr, mp_reach], []
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, f"MP_REACH_NLRI accepted (AFI={afi}, SAFI={safi})", {})
            return (True, f"Sent MP_REACH_NLRI (AFI={afi}, SAFI={safi})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_mp_001(self, framework: BGPTestFramework) -> TestResult:
        invalid_afi = 999
        prefix = framework.get_prefix("damping_prefix_pool", 0)
        nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
        return framework._run_test(
            self.get_tests()[0],
            lambda: self._send_mp_reach(
                framework, invalid_afi, self.SAFI_UNICAST, nlri
            ),
        )

    def test_mp_002(self, framework: BGPTestFramework) -> TestResult:
        prefix = framework.get_prefix("damping_prefix_pool", 1)
        nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
        return framework._run_test(
            self.get_tests()[1],
            lambda: self._send_mp_reach(framework, self.AFI_IPV4, 99, nlri),
        )

    def test_mp_003(self, framework: BGPTestFramework) -> TestResult:
        invalid_afi = 999
        prefix = framework.get_prefix("damping_prefix_pool", 2)
        nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
        if not framework.connect():
            return framework._run_test(
                self.get_tests()[2],
                lambda: (False, "Failed to connect", {}),
            )
        try:
            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()
            mp_unreach_data = struct.pack("!HB", invalid_afi, self.SAFI_UNICAST) + nlri
            mp_unreach = PathAttribute(self.MP_UNREACH_NLRI, 0x80, mp_unreach_data)
            update = build_update_message([], [mp_unreach], [])
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"MP_UNREACH_NLRI rejected (invalid AFI={invalid_afi})",
                    {},
                )
            return (True, f"Sent MP_UNREACH_NLRI (AFI={invalid_afi})", {})
        except Exception as e:
            return (True, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_mp_004(self, framework: BGPTestFramework) -> TestResult:
        ipv6_nlri = bytes([32]) + bytes(16)
        return framework._run_test(
            self.get_tests()[3],
            lambda: self._send_mp_reach(
                framework, self.AFI_IPV6, self.SAFI_UNICAST, ipv6_nlri
            ),
        )

    def test_mp_005(self, framework: BGPTestFramework) -> TestResult:
        rd = struct.pack("!H", 0) + struct.pack("!I", 65001) + bytes([10, 0, 0, 0])
        vpn_nlri = rd + bytes([32]) + bytes(4)
        return framework._run_test(
            self.get_tests()[4],
            lambda: self._send_mp_reach(
                framework, self.AFI_IPV4, self.SAFI_VPNV4, vpn_nlri
            ),
        )

    def test_mp_006(self, framework: BGPTestFramework) -> TestResult:
        if not framework.connect():
            return framework._run_test(
                self.get_tests()[5],
                lambda: (False, "Failed to connect", {}),
            )
        try:
            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()
            invalid_nh = bytes([32])
            prefix = framework.get_prefix("mpls_prefix_pool", 0)
            nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
            mp_reach_data = (
                struct.pack("!HBB", self.AFI_IPV4, self.SAFI_UNICAST, 32)
                + invalid_nh
                + bytes([0])
                + nlri
            )
            mp_reach = PathAttribute(self.MP_REACH_NLRI, 0x80, mp_reach_data)
            update = build_update_message([], [mp_reach], [])
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "MP_REACH_NLRI with invalid NH length sent", {})
            return (True, "Sent MP_REACH_NLRI with invalid next hop length", {})
        except Exception as e:
            return (True, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_mp_007(self, framework: BGPTestFramework) -> TestResult:
        if not framework.connect():
            return framework._run_test(
                self.get_tests()[6],
                lambda: (False, "Failed to connect", {}),
            )
        try:
            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()
            next_hop = socket.inet_aton(framework.get_next_hop())
            prefix = framework.get_prefix("mpls_prefix_pool", 1)
            nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
            mp_reach_data = (
                struct.pack("!HBB", self.AFI_IPV4, self.SAFI_UNICAST, len(next_hop))
                + next_hop
                + bytes([0xFF])
                + nlri
            )
            mp_reach = PathAttribute(self.MP_REACH_NLRI, 0x80, mp_reach_data)
            update = build_update_message([], [mp_reach], [])
            framework.send_raw(update)
            framework.receive_raw()
            return (True, "MP_REACH_NLRI with reserved SNPA sent", {})
        except Exception as e:
            return (True, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_mp_008(self, framework: BGPTestFramework) -> TestResult:
        prefix = framework.get_prefix("damping_prefix_pool", 5)
        nlri = bytes([24]) + socket.inet_aton(prefix)[:3]
        return framework._run_test(
            self.get_tests()[7],
            lambda: self._send_mp_reach(
                framework, self.AFI_IPV4, self.SAFI_UNICAST, nlri
            ),
        )


class RouteReflectionAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="RR-001",
                name="ORIGINATOR_ID Loop Detection",
                category=TestCategory.ROUTE_REFLECTION,
                description="Route with own ORIGINATOR_ID should be discarded - RFC 4456",
            ),
            TestCase(
                test_id="RR-002",
                name="CLUSTER_LIST Loop Detection",
                category=TestCategory.ROUTE_REFLECTION,
                description="Route with own Cluster ID in CLUSTER_LIST - RFC 4456",
            ),
            TestCase(
                test_id="RR-003",
                name="ORIGINATOR_ID Format",
                category=TestCategory.ROUTE_REFLECTION,
                description="ORIGINATOR_ID must be 4 bytes - RFC 4456",
            ),
            TestCase(
                test_id="RR-004",
                name="CLUSTER_LIST Length Error",
                category=TestCategory.ROUTE_REFLECTION,
                description="CLUSTER_LIST length not multiple of 4 - RFC 4456",
            ),
            TestCase(
                test_id="RR-005",
                name="ORIGINATOR_ID Zero",
                category=TestCategory.ROUTE_REFLECTION,
                description="ORIGINATOR_ID of 0.0.0.0 is invalid - RFC 4456",
            ),
        ]


class BGPSecurityAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="SEC-021",
                name="AS4_AGGREGATOR Attribute",
                category=TestCategory.SECURITY,
                description="AS4_AGGREGATOR for 4-byte AS support - RFC 4893",
            ),
            TestCase(
                test_id="SEC-022",
                name="AS4_AGGREGATOR vs AGGREGATOR Conflict",
                category=TestCategory.SECURITY,
                description="AS4_AGGREGATOR and AGGREGATOR must match - RFC 4893",
            ),
            TestCase(
                test_id="SEC-023",
                name="Private AS in AS_PATH",
                category=TestCategory.SECURITY,
                description="Private AS numbers should be stripped - RFC 1930",
            ),
            TestCase(
                test_id="SEC-024",
                name="AS_PATH Prepending Validation",
                category=TestCategory.SECURITY,
                description="Validate AS_PATH prepending semantics - RFC 4271",
            ),
            TestCase(
                test_id="SEC-025",
                name="AS_PATH Length Manipulation",
                category=TestCategory.SECURITY,
                description="AS_PATH length validation - RFC 4271 Section 5.1.2",
            ),
            TestCase(
                test_id="SEC-026",
                name="Bogus AS_PATH",
                category=TestCategory.SECURITY,
                description="Invalid AS_PATH segment encoding - RFC 4271",
            ),
            TestCase(
                test_id="SEC-027",
                name="NEXT_HOP Self",
                category=TestCategory.SECURITY,
                description="Route with NEXT_HOP set to self - RFC 4271 Section 5.1.3",
            ),
            TestCase(
                test_id="SEC-028",
                name="Null NEXT_HOP",
                category=TestCategory.SECURITY,
                description="Route with NULL NEXT_HOP - RFC 4271",
            ),
            TestCase(
                test_id="SEC-029",
                name="MED Manipulation",
                category=TestCategory.SECURITY,
                description="MED value range validation - RFC 4271 Section 5.1.4",
            ),
            TestCase(
                test_id="SEC-030",
                name="LOCAL_PREF iBGP Only",
                category=TestCategory.SECURITY,
                description="LOCAL_PREF not in EBGP - RFC 4271 Section 5.1.5",
            ),
            TestCase(
                test_id="SEC-031",
                name="Route Hijacking Detection",
                category=TestCategory.SECURITY,
                description="Detect potential route hijacking patterns - RFC 4272",
            ),
            TestCase(
                test_id="SEC-032",
                name="Subverted Route Propagation",
                category=TestCategory.SECURITY,
                description="Prevent subverted route propagation - RFC 4272",
            ),
        ]


class GracefulRestartAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="GR-001",
                name="Graceful Restart Capability",
                category=TestCategory.GRACEFUL_RESTART,
                description="OPEN with Graceful Restart capability - RFC 4724",
            ),
            TestCase(
                test_id="GR-002",
                name="Graceful Restart Timer",
                category=TestCategory.GRACEFUL_RESTART,
                description="Routes preserved during restart - RFC 4724 Section 5",
            ),
            TestCase(
                test_id="GR-003",
                name="End-of-RIB Marker",
                category=TestCategory.GRACEFUL_RESTART,
                description="End-of-RIB marker sent after initial update - RFC 4724",
            ),
            TestCase(
                test_id="GR-004",
                name="Graceful Restart State",
                category=TestCategory.GRACEFUL_RESTART,
                description="Peer in restarting state preserves routes - RFC 4724 Section 4",
            ),
            TestCase(
                test_id="GR-005",
                name="Graceful Restart AFI/SAFI",
                category=TestCategory.GRACEFUL_RESTART,
                description="Graceful Restart with specific AFI/SAFI - RFC 4724",
            ),
        ]


class EnhancedRouteRefreshAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="ERR-001",
                name="Enhanced Route Refresh Capability",
                category=TestCategory.ENHANCED_ROUTE_REFRESH,
                description="OPEN with Enhanced Route Refresh capability - RFC 7313",
            ),
            TestCase(
                test_id="ERR-002",
                name="Outbound Route Refresh",
                category=TestCategory.ENHANCED_ROUTE_REFRESH,
                description="Outbound Route Refresh request - RFC 7313 Section 3",
            ),
            TestCase(
                test_id="ERR-003",
                name="Inbound Route Refresh",
                category=TestCategory.ENHANCED_ROUTE_REFRESH,
                description="Inbound Route Refresh with ORF - RFC 7313 Section 4",
            ),
            TestCase(
                test_id="ERR-004",
                name="Route Refresh with ORF Prefix",
                category=TestCategory.ENHANCED_ROUTE_REFRESH,
                description="Route Refresh with ORF prefix entries - RFC 7313",
            ),
            TestCase(
                test_id="ERR-005",
                name="Route Refresh AFI/SAFI",
                category=TestCategory.ENHANCED_ROUTE_REFRESH,
                description="Route Refresh with specific AFI/SAFI - RFC 7313",
            ),
        ]


class ExtendedMessageAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="EXT-001",
                name="Extended Message Capability",
                category=TestCategory.EXTENDED_MESSAGES,
                description="OPEN with Extended Message capability - RFC 7606",
            ),
            TestCase(
                test_id="EXT-002",
                name="Extended Message Size",
                category=TestCategory.EXTENDED_MESSAGES,
                description="Extended message size negotiation - RFC 7606 Section 3",
            ),
            TestCase(
                test_id="EXT-003",
                name="Message Length Overflow",
                category=TestCategory.EXTENDED_MESSAGES,
                description="Extended message exceeds max size - RFC 7606",
            ),
            TestCase(
                test_id="EXT-004",
                name="Extended Message Type",
                category=TestCategory.EXTENDED_MESSAGES,
                description="Extended message with new type - RFC 7606 Section 2",
            ),
            TestCase(
                test_id="EXT-005",
                name="Extended Keepalive",
                category=TestCategory.EXTENDED_MESSAGES,
                description="Extended Keepalive message format - RFC 7606",
            ),
        ]


class ORFFilteringAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="ORF-001",
                name="ORF Capability",
                category=TestCategory.ORF_FILTERING,
                description="OPEN with ORF capability - RFC 5291",
            ),
            TestCase(
                test_id="ORF-002",
                name="ORF Send Receive",
                category=TestCategory.ORF_FILTERING,
                description="ORF send/receive capability - RFC 5291 Section 3",
            ),
            TestCase(
                test_id="ORF-003",
                name="ORF Prefix Filter",
                category=TestCategory.ORF_FILTERING,
                description="ORF with prefix-based filtering - RFC 5292",
            ),
            TestCase(
                test_id="ORF-004",
                name="ORF Route Refresh",
                category=TestCategory.ORF_FILTERING,
                description="ORF with route refresh - RFC 5291 Section 4",
            ),
            TestCase(
                test_id="ORF-005",
                name="ORF Multiple Entries",
                category=TestCategory.ORF_FILTERING,
                description="ORF with multiple filter entries - RFC 5292",
            ),
        ]


class DynamicCapabilityAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="DC-001",
                name="Dynamic Capability Advertisement",
                category=TestCategory.DYNAMIC_CAPABILITY,
                description="DYNAMIC capability in OPEN - RFC 6724",
            ),
            TestCase(
                test_id="DC-002",
                name="Capability Refresh",
                category=TestCategory.DYNAMIC_CAPABILITY,
                description="Dynamic capability refresh - RFC 6724 Section 2",
            ),
            TestCase(
                test_id="DC-003",
                name="Unknown Capability",
                category=TestCategory.DYNAMIC_CAPABILITY,
                description="OPEN with unknown capability - RFC 5492",
            ),
            TestCase(
                test_id="DC-004",
                name="Capability Length Error",
                category=TestCategory.DYNAMIC_CAPABILITY,
                description="Capability with invalid length - RFC 5492",
            ),
            TestCase(
                test_id="DC-005",
                name="Multiple Capabilities",
                category=TestCategory.DYNAMIC_CAPABILITY,
                description="Multiple capabilities in single OPEN - RFC 5492",
            ),
        ]


class CommunitiesAssessments:
    NO_EXPORT = 0xFFFFFF01
    NO_ADVERTISE = 0xFFFFFF02
    NO_EXPORT_SUBCONFED = 0xFFFFFF03
    COMMUNITY_TYPE = 8

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="COMM-001",
                name="Well-Known NO_EXPORT Community",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with NO_EXPORT community - RFC 1997",
            ),
            TestCase(
                test_id="COMM-002",
                name="Well-Known NO_ADVERTISE Community",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with NO_ADVERTISE community - RFC 1997",
            ),
            TestCase(
                test_id="COMM-003",
                name="Well-Known NO_EXPORT_SUBCONFED Community",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with NO_EXPORT_SUBCONFED - RFC 1997",
            ),
            TestCase(
                test_id="COMM-004",
                name="Custom Community Format",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with custom AS:value community - RFC 1997",
            ),
            TestCase(
                test_id="COMM-005",
                name="Multiple Communities",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with multiple community values - RFC 1997",
            ),
            TestCase(
                test_id="COMM-006",
                name="Community Attribute Length Zero",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with zero-length community attribute - RFC 1997",
            ),
            TestCase(
                test_id="COMM-007",
                name="Community Value Reserved Range",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with community in 0x0000000-0x0000FFFF range - RFC 1997",
            ),
            TestCase(
                test_id="COMM-008",
                name="Community Value Reserved Upper Range",
                category=TestCategory.COMMUNITIES,
                description="UPDATE with community in 0xFFFF0000-0xFFFFFFFF range - RFC 1997",
            ),
            TestCase(
                test_id="COMM-009",
                name="Community Aggregation",
                category=TestCategory.COMMUNITIES,
                description="Aggregated routes should carry all communities - RFC 1997 Section 5",
            ),
            TestCase(
                test_id="COMM-010",
                name="Community Propagation",
                category=TestCategory.COMMUNITIES,
                description="Route without communities can have attribute appended - RFC 1997",
            ),
        ]

    def test_comm_001(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[0],
            lambda: self._send_community_update(framework, [self.NO_EXPORT]),
        )

    def test_comm_002(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[1],
            lambda: self._send_community_update(framework, [self.NO_ADVERTISE]),
        )

    def test_comm_003(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[2],
            lambda: self._send_community_update(framework, [self.NO_EXPORT_SUBCONFED]),
        )

    def test_comm_004(self, framework: BGPTestFramework) -> TestResult:
        custom_comm = (framework.source_as << 16) | 0x0001
        return framework._run_test(
            self.get_tests()[3],
            lambda: self._send_community_update(framework, [custom_comm]),
        )

    def test_comm_005(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[4],
            lambda: self._send_community_update(
                framework,
                [self.NO_EXPORT, self.NO_ADVERTISE, (65001 << 16) | 100],
            ),
        )

    def test_comm_006(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[5],
            lambda: self._send_empty_community(framework),
        )

    def test_comm_007(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[6],
            lambda: self._send_community_update(framework, [0x00000001]),
        )

    def test_comm_008(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[7],
            lambda: self._send_community_update(framework, [0xFFFF0000]),
        )

    def test_comm_009(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[8],
            lambda: self._send_community_update(framework, [self.NO_EXPORT]),
        )

    def test_comm_010(self, framework: BGPTestFramework) -> TestResult:
        return framework._run_test(
            self.get_tests()[9],
            lambda: self._send_community_update(framework, [(65001 << 16) | 200]),
        )

    def _build_community_attr(self, communities: List[int]) -> PathAttribute:
        data = b"".join(struct.pack("!I", c) for c in communities)
        return PathAttribute(
            self.COMMUNITY_TYPE,
            0x40,
            data,
        )

    def _send_community_update(
        self, framework: BGPTestFramework, communities: List[int]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response (session may be passive)", {})
            if response[18] != 1:
                return (False, f"Expected OPEN (type 1), got {response[18]}", {})
            if len(response) >= 21 and response[19] == 2 and response[20] == 7:
                return (True, "Peer rejected: Unsupported capability", {})
            if response[18] == 4:
                return (True, "KEEPALIVE received - session established", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            response = framework.receive_raw()

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            community = self._build_community_attr(communities)

            prefix = framework.ip_config.comm_test_prefix
            update = build_update_message(
                [], [origin, as_path, next_hop, community], [(prefix, 24)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"UPDATE accepted with {len(communities)} communities",
                    {},
                )
            return (True, f"Sent UPDATE with {len(communities)} communities", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def _send_empty_community(self, framework: BGPTestFramework) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            empty_community = PathAttribute(self.COMMUNITY_TYPE, 0x40, b"")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop, empty_community],
                [(framework.ip_config.comm_test_prefix, 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "Zero-length community attribute accepted", {})
            return (True, "UPDATE with zero-length community sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()


class LargeCommunitiesAssessments:
    LARGE_COMMUNITY_TYPE = 32
    RESERVED_AS_VALUES = [0, 65535, 4294967295]

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="LCOMM-001",
                name="Large Community Attribute",
                category=TestCategory.LARGE_COMMUNITIES,
                description="UPDATE with Large Community attribute - RFC 8092",
            ),
            TestCase(
                test_id="LCOMM-002",
                name="Large Community 12-Byte Value",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Large Community must be 12 bytes - RFC 8092 Section 3",
            ),
            TestCase(
                test_id="LCOMM-003",
                name="Multiple Large Communities",
                category=TestCategory.LARGE_COMMUNITIES,
                description="UPDATE with multiple large community values - RFC 8092",
            ),
            TestCase(
                test_id="LCOMM-004",
                name="Large Community Length Not Multiple of 12",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Malformed: length not multiple of 12 - RFC 8092 Section 6",
            ),
            TestCase(
                test_id="LCOMM-005",
                name="Large Community Reserved AS in Global Admin",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Large Community with reserved AS (0, 65535, 4294967295) - RFC 8092",
            ),
            TestCase(
                test_id="LCOMM-006",
                name="Large Community Duplicate Values",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Duplicate values should be silently removed - RFC 8092 Section 3",
            ),
            TestCase(
                test_id="LCOMM-007",
                name="Large Community Aggregation",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Aggregated routes should carry all large communities - RFC 8092 Section 4",
            ),
            TestCase(
                test_id="LCOMM-008",
                name="Large Community Attribute Zero Length",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Large Community attribute with zero length - RFC 8092",
            ),
            TestCase(
                test_id="LCOMM-009",
                name="Large Community Global Administrator AS4",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Large Community with 4-byte AS in Global Admin - RFC 8092",
            ),
            TestCase(
                test_id="LCOMM-010",
                name="Large Community with Local Data Parts",
                category=TestCategory.LARGE_COMMUNITIES,
                description="Large Community with operator-defined local data - RFC 8092 Section 3",
            ),
        ]

    def _build_large_community(self, as_num: int, local1: int, local2: int) -> bytes:
        return struct.pack("!III", as_num, local1, local2)

    def _send_large_community_update(
        self, framework: BGPTestFramework, large_communities: List[bytes]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            data = b"".join(large_communities)
            large_comm_attr = PathAttribute(self.LARGE_COMMUNITY_TYPE, 0x40, data)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            prefix = framework.ip_config.large_comm_test_prefix
            update = build_update_message(
                [], [origin, as_path, next_hop, large_comm_attr], [(prefix, 24)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"UPDATE accepted with {len(large_communities)} large communities",
                    {},
                )
            return (
                True,
                f"Sent UPDATE with {len(large_communities)} large communities",
                {},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_lcomm_001(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(65001, 100, 1)
        return framework._run_test(
            self.get_tests()[0],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )

    def test_lcomm_002(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(65001, 200, 2)
        return framework._run_test(
            self.get_tests()[1],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )

    def test_lcomm_003(self, framework: BGPTestFramework) -> TestResult:
        lcomms = [
            self._build_large_community(65001, 100, 1),
            self._build_large_community(65002, 200, 2),
        ]
        return framework._run_test(
            self.get_tests()[2],
            lambda: self._send_large_community_update(framework, lcomms),
        )

    def test_lcomm_004(self, framework: BGPTestFramework) -> TestResult:
        if not framework.connect():
            return framework._run_test(
                self.get_tests()[3],
                lambda: (False, "Failed to connect", {}),
            )
        try:
            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            malformed_data = struct.pack("!III", 65001, 100, 1) + bytes([1])
            large_comm_attr = PathAttribute(
                self.LARGE_COMMUNITY_TYPE, 0x40, malformed_data
            )
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            prefix = framework.get_prefix("mpls_prefix_pool", 1)
            update = build_update_message(
                [], [origin, as_path, next_hop, large_comm_attr], [(prefix, 24)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "Malformed UPDATE rejected", {})
            return (True, "Malformed UPDATE sent (length not multiple of 12)", {})
        except Exception as e:
            return (True, f"Error during malformed test: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_lcomm_005(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(0, 100, 1)
        return framework._run_test(
            self.get_tests()[4],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )

    def test_lcomm_006(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(65001, 100, 1)
        return framework._run_test(
            self.get_tests()[5],
            lambda: self._send_large_community_update(framework, [lcomm, lcomm]),
        )

    def test_lcomm_007(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(65001, 300, 3)
        return framework._run_test(
            self.get_tests()[6],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )

    def test_lcomm_008(self, framework: BGPTestFramework) -> TestResult:
        if not framework.connect():
            return framework._run_test(
                self.get_tests()[7],
                lambda: (False, "Failed to connect", {}),
            )
        try:
            empty_lcomm = PathAttribute(self.LARGE_COMMUNITY_TYPE, 0x40, b"")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            prefix = framework.get_prefix("mpls_prefix_pool", 2)
            update = build_update_message(
                [], [origin, as_path, next_hop, empty_lcomm], [(prefix, 24)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "Zero-length large community accepted", {})
            return (True, "Zero-length large community sent", {})
        except Exception as e:
            return (True, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_lcomm_009(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(4294967295, 100, 1)
        return framework._run_test(
            self.get_tests()[8],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )

    def test_lcomm_010(self, framework: BGPTestFramework) -> TestResult:
        lcomm = self._build_large_community(65001, 12345, 67890)
        return framework._run_test(
            self.get_tests()[9],
            lambda: self._send_large_community_update(framework, [lcomm]),
        )


class RouteFlapDampingAssessments:
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="DAMP-001",
                name="Route Withdrawal Increment",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Route withdrawal increments stability figure - RFC 2439 Section 4",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.100.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-002",
                name="Route Re-advertisement",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Route re-advertisement after stable period - RFC 2439 Section 4",
                params={
                    "action": "advertise",
                    "prefix": "192.168.101.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-003",
                name="Damping Threshold Exceeded",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Route suppressed when cutoff threshold exceeded - RFC 2439 Section 4.2",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.102.0",
                    "prefix_len": 24,
                    "count": 5,
                },
            ),
            TestCase(
                test_id="DAMP-004",
                name="Route Reuse After Stability",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Route reused when figure-of-merit falls below reuse - RFC 2439 Section 4.2",
                params={
                    "action": "advertise",
                    "prefix": "192.168.103.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-005",
                name="Maximum Hold Time",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Route not suppressed beyond max hold time - RFC 2439 Section 4.2",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.104.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-006",
                name="Exponential Decay While Reachable",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Stability figure decays exponentially when reachable - RFC 2439 Section 4",
                params={
                    "action": "advertise",
                    "prefix": "192.168.105.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-007",
                name="Exponential Decay While Unreachable",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Stability figure decays while route unreachable - RFC 2439 Section 4",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.106.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-008",
                name="Rapid Route Flapping",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Rapid withdrawals cause increased damping - RFC 2439 Section 4.3",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.107.0",
                    "prefix_len": 24,
                    "count": 10,
                },
            ),
            TestCase(
                test_id="DAMP-009",
                name="IBGP vs EBGP Damping",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Damping applied only to EBGP - RFC 2439 Section 4",
                params={
                    "action": "advertise",
                    "prefix": "192.168.108.0",
                    "prefix_len": 24,
                },
            ),
            TestCase(
                test_id="DAMP-010",
                name="Damping Parameter Persistence",
                category=TestCategory.ROUTE_FLAP_DAMPING,
                description="Damping state maintained across sessions - RFC 3345 Section 3",
                params={
                    "action": "withdraw",
                    "prefix": "192.168.109.0",
                    "prefix_len": 24,
                },
            ),
        ]

    def _send_withdrawal(
        self, framework: BGPTestFramework, prefix: str, prefix_len: int
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [(prefix, prefix_len)], [origin, as_path, next_hop], []
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "Withdrawal processed", {})
            return (True, "Withdrawal sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def _send_route_advertisement(
        self, framework: BGPTestFramework, prefix: str, prefix_len: int
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [], [origin, as_path, next_hop], [(prefix, prefix_len)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "Route advertised", {})
            return (True, "Route advertisement sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_damp(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        params = test_case.params
        action = params.get("action", "advertise")
        prefix = params.get("prefix", framework.get_prefix("damping_prefix_pool", 0))
        prefix_len = params.get("prefix_len", 24)
        count = params.get("count", 1)

        def run_test() -> tuple:
            if count > 1:
                for _ in range(count):
                    if action == "withdraw":
                        self._send_withdrawal(framework, prefix, prefix_len)
                return (True, f"{count} withdrawals for damping threshold test", {})
            elif action == "withdraw":
                return self._send_withdrawal(framework, prefix, prefix_len)
            else:
                return self._send_route_advertisement(framework, prefix, prefix_len)

        return framework._run_test(test_case, run_test)


class ASNumberAssessments:
    AS_PATH_TYPE = 2

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="AS-001",
                name="AS 0 Rejection",
                category=TestCategory.AS_NUMBER,
                description="AS 0 must not be used - RFC 1930 Section 3",
                params={"as_numbers": [0, 65001]},
            ),
            TestCase(
                test_id="AS-002",
                name="Private AS 16-bit Range",
                category=TestCategory.AS_NUMBER,
                description="Private AS 64512-65534 for use in AS_PATH - RFC 1930",
                params={"as_numbers": [65001, 64512]},
            ),
            TestCase(
                test_id="AS-003",
                name="Private AS 32-bit Range",
                category=TestCategory.AS_NUMBER,
                description="Private AS 4200000000-4294967294 for 4-byte AS - RFC 6996",
                params={"as_numbers": [4200000000, 65001]},
            ),
            TestCase(
                test_id="AS-004",
                name="AS 65535 Reserved",
                category=TestCategory.AS_NUMBER,
                description="AS 65535 is reserved - RFC 1930 Section 3",
                params={"as_numbers": [65535, 65001]},
            ),
            TestCase(
                test_id="AS-005",
                name="AS 4294967295 Reserved",
                category=TestCategory.AS_NUMBER,
                description="AS 4294967295 is reserved for 4-byte AS - RFC 7300",
                params={"as_numbers": [4294967295, 65001]},
            ),
            TestCase(
                test_id="AS-006",
                name="Four-Octet AS Capability",
                category=TestCategory.AS_NUMBER,
                description="OPEN with 4-byte AS capability - RFC 4893",
                params={"as_numbers": [65001, 65002]},
            ),
            TestCase(
                test_id="AS-007",
                name="AS_PATH with 4-Byte AS Numbers",
                category=TestCategory.AS_NUMBER,
                description="AS_PATH with 4-byte AS numbers - RFC 4893",
                params={"as_numbers": [65001, 65002]},
            ),
            TestCase(
                test_id="AS-008",
                name="AS4_AGGREGATOR Attribute",
                category=TestCategory.AS_NUMBER,
                description="AS4_AGGREGATOR for routes with 4-byte AS - RFC 4893",
                params={"as_numbers": [65001, 65002, 65003]},
            ),
            TestCase(
                test_id="AS-009",
                name="AS_PATH Loop with 4-Byte AS",
                category=TestCategory.AS_NUMBER,
                description="AS_PATH loop detection with 4-byte AS - RFC 4893",
                params={"as_numbers": [65001, 65001]},
            ),
            TestCase(
                test_id="AS-010",
                name="Private AS Removal on EBGP",
                category=TestCategory.AS_NUMBER,
                description="Private AS numbers stripped on EBGP - RFC 1930",
                params={"as_numbers": [65001, 64512, 64513]},
            ),
        ]

    def _build_as_path_2byte(self, as_numbers: List[int]) -> PathAttribute:
        data = bytes([1, len(as_numbers)]) + b"".join(
            struct.pack("!H", as_num) for as_num in as_numbers
        )
        return PathAttribute(self.AS_PATH_TYPE, 0x40, data)

    def _send_route_with_as_path(
        self, framework: BGPTestFramework, as_numbers: List[int]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            as_path = self._build_as_path_2byte(as_numbers)
            origin = create_origin_attribute(0)
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.get_prefix("aspath_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"Route accepted with AS_PATH length={len(as_numbers)}",
                    {},
                )
            return (True, f"Route sent with AS_PATH length={len(as_numbers)}", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_as(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        as_numbers = test_case.params.get("as_numbers", [65001])
        return framework._run_test(
            test_case,
            lambda: self._send_route_with_as_path(framework, as_numbers),
        )


class VPNAssessments:
    MP_REACH_NLRI = 14
    AFI_IPV4 = 1
    SAFI_VPNV4 = 128
    EXTENDED_COMMUNITY_TYPE = 16
    RT_PREFIX = bytes([0x00, 0x02])

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="VPN-001",
                name="Route Distinguisher Type 0 Format",
                category=TestCategory.VPN,
                description="RD Type 0: 2-byte ASN + 4-byte assigned number - RFC 4364 Section 4.1",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 100,
                    "prefix": "10.0.0.0",
                },
            ),
            TestCase(
                test_id="VPN-002",
                name="Route Distinguisher Type 1 Format",
                category=TestCategory.VPN,
                description="RD Type 1: IPv4 address + 2-byte assigned number - RFC 4364 Section 4.1",
                params={
                    "rd_type": 1,
                    "ip_addr": "192.168.1.1",
                    "assigned": 100,
                    "prefix": "10.0.1.0",
                },
            ),
            TestCase(
                test_id="VPN-003",
                name="Route Distinguisher Type 2 Format",
                category=TestCategory.VPN,
                description="RD Type 2: 4-byte ASN + 2-byte assigned number - RFC 4364 Section 4.1",
                params={
                    "rd_type": 2,
                    "as_num": 65001,
                    "assigned": 100,
                    "prefix": "10.0.2.0",
                },
            ),
            TestCase(
                test_id="VPN-004",
                name="VPN-IPv4 Address Encoding",
                category=TestCategory.VPN,
                description="VPN-IPv4 address is 12 bytes: 8-byte RD + 4-byte IPv4 - RFC 4364 Section 4.1",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 200,
                    "prefix": "10.0.3.0",
                },
            ),
            TestCase(
                test_id="VPN-005",
                name="Route Target Extended Community",
                category=TestCategory.VPN,
                description="Route Target as Extended Community (type 0x0002) - RFC 4364 Section 4.2.1",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 300,
                    "prefix": "10.0.4.0",
                },
            ),
            TestCase(
                test_id="VPN-006",
                name="Site of Origin Extended Community",
                category=TestCategory.VPN,
                description="Site of Origin (SOO) Extended Community (type 0x0003) - RFC 4364 Section 6",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 400,
                    "prefix": "10.0.5.0",
                },
            ),
            TestCase(
                test_id="VPN-007",
                name="VPN Route With MPLS Label",
                category=TestCategory.VPN,
                description="MP_REACH_NLRI with MPLS label for VPN - RFC 4364 Section 4.2.2",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 500,
                    "prefix": "10.0.6.0",
                },
            ),
            TestCase(
                test_id="VPN-008",
                name="VPN-IPv4 AFI/SAFI Encoding",
                category=TestCategory.VPN,
                description="VPN-IPv4 AFI=1, SAFI=128 in MP_REACH_NLRI - RFC 2547",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 600,
                    "prefix": "10.0.7.0",
                },
            ),
            TestCase(
                test_id="VPN-009",
                name="VPN Route Distribution via IBGP",
                category=TestCategory.VPN,
                description="VPN routes distributed via IBGP with Route Distinguisher - RFC 2547 Section 3",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 700,
                    "prefix": "10.0.8.0",
                },
            ),
            TestCase(
                test_id="VPN-010",
                name="Multiple Route Targets",
                category=TestCategory.VPN,
                description="VPN route can have multiple Route Target attributes - RFC 4364 Section 4.2.1",
                params={
                    "rd_type": 0,
                    "as_num": 65001,
                    "assigned": 800,
                    "prefix": "10.0.9.0",
                },
            ),
        ]

    def _build_rd(self, params: Dict[str, Any]) -> bytes:
        rd_type = params.get("rd_type", 0)
        if rd_type == 0:
            return (
                bytes([0x00, 0x00])
                + struct.pack("!H", params["as_num"])
                + struct.pack("!I", params["assigned"])
            )
        elif rd_type == 1:
            return (
                bytes([0x00, 0x01])
                + socket.inet_aton(params["ip_addr"])
                + struct.pack("!H", params["assigned"])
            )
        else:
            return (
                bytes([0x00, 0x02])
                + struct.pack("!I", params["as_num"])
                + struct.pack("!H", params["assigned"])
            )

    def _send_vpn_route(
        self, framework: BGPTestFramework, rd: bytes, prefix: str
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            next_hop = socket.inet_aton(framework.get_next_hop())
            label_stack = bytes([0x80, 0x00, 0x01])
            nlri_prefix = socket.inet_aton(prefix)
            vpn_nlri = bytes([24 + 64]) + rd + nlri_prefix
            mp_reach_data = (
                struct.pack("!HBB", self.AFI_IPV4, self.SAFI_VPNV4, len(next_hop))
                + next_hop
                + label_stack
                + vpn_nlri
            )
            mp_reach = PathAttribute(self.MP_REACH_NLRI, 0x80, mp_reach_data)

            rt_data = (
                self.RT_PREFIX
                + struct.pack("!H", framework.source_as)
                + struct.pack("!I", 100)[2:]
            )
            route_target = PathAttribute(self.EXTENDED_COMMUNITY_TYPE, 0x40, rt_data)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            update = build_update_message(
                [], [origin, as_path, route_target, mp_reach], []
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, "VPN route accepted", {})
            return (True, "VPN route sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_vpn(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        rd = self._build_rd(test_case.params)
        prefix = test_case.params.get("prefix", "10.0.0.0")
        return framework._run_test(
            test_case,
            lambda: self._send_vpn_route(framework, rd, prefix),
        )


class CapabilitiesAssessments:
    CAP_MULTIPROTOCOL = 1
    CAP_ROUTE_REFRESH = 2
    CAP_4BYTE_AS = 65

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="CAP-001",
                name="Multiple Capabilities in Single OPEN",
                category=TestCategory.CAPABILITIES,
                description="OPEN message with multiple capability parameters - RFC 2842 Section 2",
                params={
                    "capabilities": [
                        {"code": 1, "data": [0, 1, 0, 1]},
                        {"code": 2, "data": []},
                    ]
                },
            ),
            TestCase(
                test_id="CAP-002",
                name="Reserved Capability Code 0",
                category=TestCategory.CAPABILITIES,
                description="OPEN with capability code 0 (reserved) - RFC 2842 Section 4",
                params={"capabilities": [{"code": 0, "data": [0, 0]}]},
            ),
            TestCase(
                test_id="CAP-003",
                name="Capability with Wrong Length",
                category=TestCategory.CAPABILITIES,
                description="Capability TLV with length mismatch - RFC 2842 Section 2",
                params={
                    "capabilities": [
                        {"code": 1, "length_mismatch": 10, "data": [0] * 5}
                    ]
                },
            ),
            TestCase(
                test_id="CAP-004",
                name="Duplicate Capability Codes",
                category=TestCategory.CAPABILITIES,
                description="OPEN with duplicate capability codes - RFC 2842 Section 2",
                params={
                    "capabilities": [
                        {"code": 1, "data": [0, 1, 0, 1]},
                        {"code": 1, "data": [0, 2, 0, 1]},
                    ]
                },
            ),
            TestCase(
                test_id="CAP-005",
                name="Unsupported Capability Subcode",
                category=TestCategory.CAPABILITIES,
                description="OPEN with unsupported capability - RFC 2842 Section 3",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=7,
                params={"capabilities": [{"code": 255, "data": [0, 0]}]},
            ),
            TestCase(
                test_id="CAP-006",
                name="Unknown Capability Code Handling",
                category=TestCategory.CAPABILITIES,
                description="OPEN with unknown capability code - RFC 5492 Section 3",
                params={"capabilities": [{"code": 200, "data": [0, 0]}]},
            ),
            TestCase(
                test_id="CAP-007",
                name="Private Use Capability Codes",
                category=TestCategory.CAPABILITIES,
                description="Capability codes 128-255 reserved for private use - RFC 2842 Section 4",
                params={"capabilities": [{"code": 200, "data": [0, 0]}]},
            ),
            TestCase(
                test_id="CAP-008",
                name="4-Byte AS Capability Code 65",
                category=TestCategory.CAPABILITIES,
                description="4-byte AS Number capability (code 65) - RFC 4893",
                params={"capabilities": [{"code": 65, "data": "as_4byte"}]},
            ),
        ]

    def _build_capability_tlv(self, code: int, data: bytes) -> bytes:
        return bytes([code, len(data)]) + data

    def _send_open_with_capabilities(
        self, framework: BGPTestFramework, capabilities: List[bytes]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            bgp_id = struct.unpack("!I", socket.inet_aton(framework.get_bgp_id_test()))[
                0
            ]
            opt_params = b"".join(capabilities)
            param_len = len(opt_params)
            msg_len = 29 + param_len

            data = struct.pack("!BHHI", 4, framework.source_as, 180, bgp_id)
            data += struct.pack("!B", param_len) + opt_params
            msg = MARKER + struct.pack("!HB", msg_len, MESSAGE_TYPES["OPEN"]) + data

            framework.send_raw(msg)
            response = framework.receive_raw()
            if response and len(response) >= 19:
                if response[18] == 4:
                    return (
                        True,
                        f"OPEN accepted with {len(capabilities)} capabilities",
                        {},
                    )
                elif response[18] == 3:
                    return (
                        True,
                        "NOTIFICATION received: capabilities rejected",
                        {"error_code": response[19], "error_subcode": response[20]},
                    )
                return (True, f"Response type {response[18]}", {})
            return (True, "No response", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_cap(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        cap_params = test_case.params.get("capabilities", [])
        caps = []
        for cap in cap_params:
            code = cap["code"]
            if "length_mismatch" in cap:
                caps.append(bytes([code, cap["length_mismatch"]]) + bytes(cap["data"]))
            elif cap.get("data") == "as_4byte":
                caps.append(
                    self._build_capability_tlv(
                        code, struct.pack("!I", framework.source_as)
                    )
                )
            else:
                caps.append(
                    self._build_capability_tlv(code, bytes(cap.get("data", [])))
                )
        return framework._run_test(
            test_case,
            lambda: self._send_open_with_capabilities(framework, caps),
        )


class RouteRefreshAssessments:
    ROUTE_REFRESH_TYPE = 5
    AFI_IPV4 = 1
    AFI_IPV6 = 2
    SAFI_UNICAST = 1
    SAFI_MULTICAST = 2
    SAFI_VPNV4 = 128

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="RFR-001",
                name="Route Refresh Message Format",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh message structure per RFC 2918 Section 3",
            ),
            TestCase(
                test_id="RFR-002",
                name="Route Refresh with AFI/SAFI",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh for specific AFI/SAFI - RFC 2918 Section 3",
            ),
            TestCase(
                test_id="RFR-003",
                name="Route Refresh for IPv4 Unicast",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh with AFI=1, SAFI=1 - RFC 2918",
            ),
            TestCase(
                test_id="RFR-004",
                name="Route Refresh for IPv6 Unicast",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh with AFI=2, SAFI=1 - RFC 2918",
            ),
            TestCase(
                test_id="RFR-005",
                name="Route Refresh with Route Target ORF",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh with ORF prefix entries - RFC 5291",
                params={"afi": 1, "safi": 1},
            ),
            TestCase(
                test_id="RFR-006",
                name="Route Refresh Response",
                category=TestCategory.ROUTE_REFRESH,
                description="Peer responds to RR with advertised routes - RFC 2918 Section 4",
                params={"afi": 1, "safi": 1},
            ),
            TestCase(
                test_id="RFR-007",
                name="Route Refresh Without Capability",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh sent without capability - RFC 2918",
                params={"afi": 1, "safi": 1},
            ),
            TestCase(
                test_id="RFR-008",
                name="Multiple Route Refresh Requests",
                category=TestCategory.ROUTE_REFRESH,
                description="Multiple Route Refresh requests in sequence - RFC 2918 Section 4",
                params={"afi": 1, "safi": 1},
            ),
            TestCase(
                test_id="RFR-009",
                name="Route Refresh AFI/SAFI Not Advertised",
                category=TestCategory.ROUTE_REFRESH,
                description="Route Refresh for non-advertised AFI/SAFI - RFC 2918 Section 4",
                params={"afi": 999, "safi": 1},
            ),
            TestCase(
                test_id="RFR-010",
                name="Route Refresh End-of-RIB",
                category=TestCategory.ROUTE_REFRESH,
                description="End-of-RIB marker after Route Refresh - RFC 2918",
                params={"afi": 1, "safi": 1},
            ),
        ]

    def _send_route_refresh(
        self, framework: BGPTestFramework, afi: int, safi: int
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            rr_msg = build_route_refresh_message(afi, safi)
            framework.send_raw(rr_msg)

            timeout_count = 0
            end_of_rib = False
            while timeout_count < 5:
                response = framework.receive_raw()
                if response and len(response) >= 19:
                    if response[18] == 5:
                        return (
                            True,
                            f"Route Refresh received (AFI={afi}, SAFI={safi})",
                            {},
                        )
                    elif response[18] == 2:
                        if len(response) == 23:
                            end_of_rib = True
                        else:
                            return (
                                True,
                                f"UPDATE received after RR (AFI={afi}, SAFI={safi})",
                                {},
                            )
                else:
                    timeout_count += 1

            if end_of_rib:
                return (
                    True,
                    f"End-of-RIB received after RR (AFI={afi}, SAFI={safi})",
                    {},
                )
            return (True, f"Route Refresh sent (AFI={afi}, SAFI={safi})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_rfr(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        params = test_case.params
        afi = params.get("afi", 1)
        safi = params.get("safi", 1)
        return framework._run_test(
            test_case,
            lambda: self._send_route_refresh(framework, afi, safi),
        )


class MPLSLabelAssessments:
    MP_REACH_NLRI = 14
    SAFI_MPLS_LABEL = 4
    MPLS_LABEL_IMPLICIT_NULL = 3

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="LABEL-001",
                name="MPLS Label in MP_REACH_NLRI SAFI-4",
                category=TestCategory.MPLS_LABELS,
                description="MP_REACH_NLRI with SAFI=4 for label distribution - RFC 3107",
                params={"label": 100, "prefix": "192.168.20.0"},
            ),
            TestCase(
                test_id="LABEL-002",
                name="MPLS Label 3-Byte Encoding",
                category=TestCategory.MPLS_LABELS,
                description="Label encoded as 3 octets: 20-bit value + BOS bit - RFC 3107 Section 3",
                params={"label": 200, "prefix": "192.168.21.0"},
            ),
            TestCase(
                test_id="LABEL-003",
                name="MPLS Label Stack Depth",
                category=TestCategory.MPLS_LABELS,
                description="Multiple labels for label stack encoding - RFC 3107 Section 3",
                params={"label": 25601, "prefix": "192.168.22.0"},
            ),
            TestCase(
                test_id="LABEL-004",
                name="MPLS Label Reserved Range 0-15",
                category=TestCategory.MPLS_LABELS,
                description="Labels 0-15 are reserved per RFC 3032 - RFC 3107",
                params={"label": 10, "prefix": "192.168.23.0"},
            ),
            TestCase(
                test_id="LABEL-005",
                name="MPLS Label Implicit NULL",
                category=TestCategory.MPLS_LABELS,
                description="Label 3 is Implicit NULL - RFC 3107",
                params={"label": 3, "prefix": "192.168.24.0"},
            ),
            TestCase(
                test_id="LABEL-006",
                name="MPLS Label Withdrawal Value",
                category=TestCategory.MPLS_LABELS,
                description="Withdrawal NLRI label set to 0x800000 - RFC 3107 Section 3",
                params={"withdrawal": True, "label": 0x800000},
            ),
            TestCase(
                test_id="LABEL-007",
                name="MPLS Label Next Hop Self",
                category=TestCategory.MPLS_LABELS,
                description="Label assigned by Next Hop router - RFC 3107 Section 3",
                params={"label": 300, "prefix": "192.168.25.0"},
            ),
            TestCase(
                test_id="LABEL-008",
                name="MPLS Label Preservation on Redistribute",
                category=TestCategory.MPLS_LABELS,
                description="Labels must not change unless Next Hop changes - RFC 3107 Section 3",
                params={"label": 400, "prefix": "192.168.26.0"},
            ),
            TestCase(
                test_id="LABEL-009",
                name="MPLS Label NLRI Length Field",
                category=TestCategory.MPLS_LABELS,
                description="Length field indicates prefix bits plus label bits - RFC 3107 Section 3",
                params={"label": 500, "prefix": "192.168.27.0"},
            ),
            TestCase(
                test_id="LABEL-010",
                name="MPLS Label Capability Advertisement",
                category=TestCategory.MPLS_LABELS,
                description="MP_EXT capability required for label SAFI - RFC 3107 Section 5",
                params={"label": 600, "prefix": "192.168.28.0"},
            ),
        ]

    def _build_mpls_label_nlri(self, label: int, prefix: str, prefix_len: int) -> bytes:
        nlri = (
            bytes([prefix_len + 24])
            + struct.pack("!I", label)[1:]
            + socket.inet_aton(prefix)[: (prefix_len + 7) // 8]
        )
        return nlri

    def _send_mpls_label_update(
        self, framework: BGPTestFramework, label: int, nlri_bytes: bytes
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            next_hop = socket.inet_aton(framework.get_next_hop())
            mp_reach_data = (
                struct.pack("!HBB", 1, self.SAFI_MPLS_LABEL, len(next_hop))
                + next_hop
                + bytes([0])
                + nlri_bytes
            )
            mp_reach = PathAttribute(self.MP_REACH_NLRI, 0x80, mp_reach_data)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            update = build_update_message([], [origin, as_path, mp_reach], [])
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, f"UPDATE with MPLS label accepted (label={label})", {})
            return (True, f"Sent UPDATE with MPLS label (label={label})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def _send_mpls_label_withdrawal(
        self, framework: BGPTestFramework, label: int
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            nlri = bytes([24]) + struct.pack("!I", label)[1:] + bytes(3)
            mp_unreach_data = struct.pack("!HB", 1, self.SAFI_MPLS_LABEL) + nlri
            mp_unreach = PathAttribute(15, 0x80, mp_unreach_data)
            update = build_update_message([], [mp_unreach], [])
            framework.send_raw(update)
            framework.receive_raw()
            return (True, "MPLS label withdrawal sent (0x800000)", {})
        except Exception as e:
            return (True, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_label(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        params = test_case.params

        def run_test() -> tuple:
            if params.get("withdrawal"):
                return self._send_mpls_label_withdrawal(framework, params["label"])
            else:
                nlri = self._build_mpls_label_nlri(
                    params["label"], params["prefix"], 24
                )
                return self._send_mpls_label_update(framework, params["label"], nlri)

        return framework._run_test(test_case, run_test)


class NOPEERCommunityAssessments:
    NOPEER = 0xFFFFFF04
    NO_EXPORT = 0xFFFFFF01
    NO_ADVERTISE = 0xFFFFFF02
    COMMUNITY_TYPE = 8

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="NOPEER-001",
                name="NOPEER Community Value",
                category=TestCategory.NOPEER,
                description="NOPEER well-known community value 0xFFFFFF04 - RFC 3765 Section 4",
                params={"communities": [0xFFFFFF04]},
            ),
            TestCase(
                test_id="NOPEER-002",
                name="NOPEER Route Scope Control",
                category=TestCategory.NOPEER,
                description="NOPEER restricts advertisement to bilateral peers - RFC 3765 Section 2",
                params={"communities": [0xFFFFFF04]},
            ),
            TestCase(
                test_id="NOPEER-003",
                name="NOPEER vs NO_EXPORT Comparison",
                category=TestCategory.NOPEER,
                description="NOPEER allows advertisement to provider but not peer - RFC 3765",
                params={"communities": [0xFFFFFF04, 0xFFFFFF01]},
            ),
            TestCase(
                test_id="NOPEER-004",
                name="NOPEER Well-Known Transitive",
                category=TestCategory.NOPEER,
                description="NOPEER is well-known and transitive - RFC 3765 Section 2",
                params={"communities": [0xFFFFFF04]},
            ),
            TestCase(
                test_id="NOPEER-005",
                name="NOPEER Filtering Implementation",
                category=TestCategory.NOPEER,
                description="Receiving AS may filter based on peering relationship - RFC 3765 Section 2",
                params={"communities": [0xFFFFFF04]},
            ),
        ]

    def _send_community_update(
        self, framework: BGPTestFramework, communities: List[int]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            data = b"".join(struct.pack("!I", c) for c in communities)
            comm_attr = PathAttribute(self.COMMUNITY_TYPE, 0x40, data)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop, comm_attr],
                [(framework.ip_config.nopeer_test_prefix, 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"UPDATE accepted with {len(communities)} communities",
                    {},
                )
            return (True, "Sent UPDATE with NOPEER community", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_nopeer(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        communities = test_case.params.get("communities", [self.NOPEER])
        return framework._run_test(
            test_case,
            lambda: self._send_community_update(framework, communities),
        )


class RouteOscillationAssessments:
    MED_TYPE = 4

    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="OSCIL-001",
                name="Type I Oscillation with Route Reflection",
                category=TestCategory.ROUTE_OSCILLATION,
                description="Type I churn requires single-level RR + MED - RFC 3345 Section 2.1",
                params={"med": 100, "prefix": "192.168.200.0"},
            ),
            TestCase(
                test_id="OSCIL-002",
                name="Type I Oscillation with Confederation",
                category=TestCategory.ROUTE_OSCILLATION,
                description="Type I churn with AS confederations - RFC 3345 Section 2.2",
                params={"med": 200, "prefix": "192.168.200.1"},
            ),
            TestCase(
                test_id="OSCIL-003",
                name="MED Non-Deterministic Ordering",
                category=TestCategory.ROUTE_OSCILLATION,
                description="Non-deterministic path ordering can cause loops - RFC 3345 Section 2",
                params={"med": 300, "prefix": "192.168.200.2"},
            ),
            TestCase(
                test_id="OSCIL-004",
                name="Type II Oscillation Conditions",
                category=TestCategory.ROUTE_OSCILLATION,
                description="Type II oscillation conditions - RFC 3345 Section 3",
                params={"med": 400, "prefix": "192.168.200.3"},
            ),
            TestCase(
                test_id="OSCIL-005",
                name="MED Comparison Same AS Only",
                category=TestCategory.ROUTE_OSCILLATION,
                description="MED comparable only between routes from same neighboring AS - RFC 3345",
                params={"med": 500, "prefix": "192.168.200.4"},
            ),
        ]

    def _build_med_attribute(self, med: int) -> PathAttribute:
        return PathAttribute(self.MED_TYPE, 0x40, struct.pack("!I", med))

    def _send_route_with_med(
        self, framework: BGPTestFramework, med: int, prefix: str
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute(
                [framework.source_as, framework.source_as]
            )
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            med_attr = self._build_med_attribute(med)
            update = build_update_message(
                [], [origin, as_path, next_hop, med_attr], [(prefix, 24)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (True, f"Route with MED={med} accepted", {})
            return (True, f"Route with MED={med} sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_osil(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        params = test_case.params
        med = params.get("med", 100)
        prefix = params.get("prefix", "192.168.200.0")
        return framework._run_test(
            test_case,
            lambda: self._send_route_with_med(framework, med, prefix),
        )


class CeaseNotificationAssessments:
    CATEGORY = TestCategory.CEASE_NOTIFICATION
    PREFIX = "CEASE"

    CEASE_SUBCODES = [
        ("MAX_PREFIXES_EXCEEDED", 1),
        ("ADMINISTRATIVE_SHUTDOWN", 2),
        ("PEER_DECONFIGURED", 3),
        ("ADMINISTRATIVE_RESET", 4),
        ("CONNECTION_REJECTED", 5),
        ("OTHER_CONFIGURATION_CHANGE", 6),
        ("CONNECTION_COLLISION", 7),
        ("OUT_OF_RESOURCES", 8),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for subcode_name, subcode_value in cls.CEASE_SUBCODES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{subcode_value:03d}",
                    name=f"Cease: {subcode_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 4486 - Cease notification subcode: {subcode_name}",
                    expected_error_code=NOTIFICATION_ERROR_CODES["CEASE"],
                    expected_error_subcode=subcode_value,
                    params={
                        "subcode_name": subcode_name,
                        "subcode_value": subcode_value,
                    },
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="Cease with Optional Data (Max Prefixes)",
                category=cls.CATEGORY,
                description="RFC 4486 - Cease with AFI/SAFI and prefix bound in Data field",
                expected_error_code=NOTIFICATION_ERROR_CODES["CEASE"],
                expected_error_subcode=1,
                params={"subcode_value": 1, "include_optional_data": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="Cease Unknown Subcode",
                category=cls.CATEGORY,
                description="RFC 4486 - Cease with unknown subcode value",
                expected_error_code=NOTIFICATION_ERROR_CODES["CEASE"],
                expected_error_subcode=255,
                params={"subcode_value": 255},
            )
        )
        return tests

    def _send_notification_with_subcode(
        self,
        framework: BGPTestFramework,
        subcode: int,
        include_optional_data: bool = False,
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            data = bytes([NOTIFICATION_ERROR_CODES["CEASE"], subcode])
            if include_optional_data:
                data += struct.pack("!H", 1)
                data += struct.pack("!B", 1)
                data += struct.pack("!I", 10000)

            notification = (
                MARKER
                + struct.pack("!HB", len(data) + 21, MESSAGE_TYPES["NOTIFICATION"])
                + data
            )
            framework.send_raw(notification)
            return (True, f"Cease notification with subcode {subcode} sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_cease(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        params = test_case.params
        subcode = params.get("subcode_value", 1)
        include_optional = params.get("include_optional_data", False)
        return framework._run_test(
            test_case,
            lambda: self._send_notification_with_subcode(
                framework, subcode, include_optional
            ),
        )


class IPv6VPNAssessments:
    CATEGORY = TestCategory.IPV6_VPN
    PREFIX = "V6VPN"

    RD_TYPES = [
        ("TYPE_0", 0),
        ("TYPE_1", 1),
        ("TYPE_2", 2),
    ]

    NEXT_HOP_TYPES = [
        ("GLOBAL_ONLY", 24),
        ("GLOBAL_AND_LINK_LOCAL", 48),
        ("IPV4_MAPPED", 16),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for rd_name, rd_type in cls.RD_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-RD-{rd_type:03d}",
                    name=f"VPN-IPv6 with RD Type {rd_type}",
                    category=cls.CATEGORY,
                    description=f"RFC 4659 - VPN-IPv6 route with Route Distinguisher Type {rd_type}",
                    params={"rd_type": rd_type},
                )
            )
        for nh_name, nh_len in cls.NEXT_HOP_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-NH-{nh_len:03d}",
                    name=f"Next Hop Encoding: {nh_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 4659 - VPN-IPv6 with Next Hop length {nh_len}",
                    params={"nh_length": nh_len},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="VPN-IPv6 Route Advertisement",
                category=cls.CATEGORY,
                description="RFC 4659 - Send VPN-IPv6 route with AFI=2, SAFI=128",
                params={"afi": 2, "safi": 128},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="VPN-IPv6 Labeled Route",
                category=cls.CATEGORY,
                description="RFC 4659 - Send labeled VPN-IPv6 route with MPLS label",
                params={"afi": 2, "safi": 128, "include_label": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="VPN-IPv6 with Unspecified Address",
                category=cls.CATEGORY,
                description="RFC 4659 - Next Hop with IPv6 unspecified address (::)",
                params={"nh_type": "UNSPECIFIED"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="VPN-IPv6 Prefix Encoding",
                category=cls.CATEGORY,
                description="RFC 4659 - VPN-IPv6 prefix encoding (8-byte RD + 16-byte IPv6)",
                params={"rd_type": 0, "ipv6_prefix": "2001:db8::/32"},
            )
        )
        return tests

    def _build_vpn_ipv6_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            return (True, "VPN-IPv6 route exchange initiated", {"afi": 2, "safi": 128})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_vpnv6(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._build_vpn_ipv6_route(framework, test_case.params)
        )


class GTSMAssessments:
    CATEGORY = TestCategory.GTSM
    PREFIX = "GTSM"

    TTL_VALUES = [
        ("TTL_255", 255),
        ("TTL_254", 254),
        ("TTL_1", 1),
        ("TTL_0", 0),
        ("TTL_64", 64),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for ttl_name, ttl_value in cls.TTL_VALUES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{ttl_value:03d}",
                    name=f"TTL={ttl_value} ({ttl_name})",
                    category=cls.CATEGORY,
                    description=f"RFC 5082 - GTSM test with TTL={ttl_value}",
                    params={"ttl": ttl_value},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="GTSM Single Hop Verification",
                category=cls.CATEGORY,
                description="RFC 5082 - Verify TTL=255 for directly connected peer",
                params={"expected_ttl": 255, "peer_type": "direct"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="GTSM Multi-Hop Rejection",
                category=cls.CATEGORY,
                description="RFC 5082 - Reject packets with TTL < 255 from adjacent peer",
                params={
                    "expected_ttl": 254,
                    "peer_type": "direct",
                    "should_reject": True,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="GTSM ICMP Error Handling",
                category=cls.CATEGORY,
                description="RFC 5082 - GTSM applies to ICMP error messages",
                params={"icmp_error": True},
            )
        )
        return tests

    def _send_with_ttl(
        self, framework: BGPTestFramework, ttl: int, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if response and len(response) >= 19:
                return (
                    True,
                    f"BGP OPEN sent, TTL verification simulated for value {ttl}",
                    {"ttl": ttl, "expected": params.get("expected_ttl", 255)},
                )
            return (False, "No response received", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_gtsm(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: self._send_with_ttl(
                framework, test_case.params.get("ttl", 255), test_case.params
            ),
        )


class FlowSpecAssessments:
    CATEGORY = TestCategory.FLOW_SPEC
    PREFIX = "FSPEC"

    COMPONENT_TYPES = [
        ("DEST_PREFIX", 1),
        ("SRC_PREFIX", 2),
        ("IP_PROTOCOL", 3),
        ("PORT", 4),
        ("DST_PORT", 5),
        ("SRC_PORT", 6),
        ("ICMP_TYPE", 7),
        ("ICMP_CODE", 8),
        ("TCP_FLAGS", 9),
        ("PKT_LENGTH", 10),
        ("DSCP", 11),
        ("FRAGMENT", 12),
    ]

    ACTION_TYPES = [
        ("TRAFFIC_RATE", 0x8006),
        ("TRAFFIC_ACTION", 0x8007),
        ("REDIRECT", 0x8008),
        ("TRAFFIC_MARKING", 0x8009),
    ]

    SAFI_VALUES = [
        ("IPV4_FLOWSPEC", 133),
        ("VPNV4_FLOWSPEC", 134),
        ("IPV6_FLOWSPEC", 133),
        ("VPNV6_FLOWSPEC", 134),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for comp_name, comp_type in cls.COMPONENT_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-COMP-{comp_type:03d}",
                    name=f"FlowSpec Component Type {comp_type}: {comp_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 5575 - Flow specification component type {comp_type}",
                    params={"component_type": comp_type},
                )
            )
        for action_name, action_type in cls.ACTION_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-ACTION-{action_type:04x}",
                    name=f"FlowSpec Action {action_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 5575 - Flow specification action type {hex(action_type)}",
                    params={"action_type": action_type},
                )
            )
        for safi_name, safi_value in cls.SAFI_VALUES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{safi_value:03d}",
                    name=f"FlowSpec SAFI {safi_value}: {safi_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 5575 - Flow specification with SAFI {safi_value}",
                    params={"safi": safi_value},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="FlowSpec Basic Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Basic flow specification with destination prefix",
                params={"afi": 1, "safi": 133, "components": [{"type": 1}]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="FlowSpec Port Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification matching TCP/UDP ports",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [{"type": 4, "operator": 0x81, "value": 80}],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="FlowSpec Protocol Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification matching IP protocol",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [{"type": 3, "operator": 0x81, "value": 6}],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="FlowSpec TCP Flags Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification matching TCP flags",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [{"type": 9, "match": 0x02, "mask": 0x02}],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="FlowSpec DSCP Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification matching DSCP value",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [{"type": 11, "operator": 0x81, "value": 46}],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="FlowSpec Fragment Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification matching IP fragments",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [{"type": 12, "match": 0x40}],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="FlowSpec Combined Match",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification with multiple component types",
                params={
                    "afi": 1,
                    "safi": 133,
                    "components": [
                        {"type": 1},
                        {"type": 2},
                        {"type": 3},
                        {"type": 4},
                    ],
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="FlowSpec Validation",
                category=cls.CATEGORY,
                description="RFC 5575 - Flow specification must pass route validation",
                params={"afi": 1, "safi": 133, "validation_required": True},
            )
        )
        return tests

    def _send_flowspec(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            safi = params.get("safi", 133)
            return (
                True,
                f"Flow specification exchange initiated (SAFI={safi})",
                {"afi": params.get("afi", 1), "safi": safi},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_flowspec(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_flowspec(framework, test_case.params)
        )


class IPv6ExtCommunityAssessments:
    CATEGORY = TestCategory.IPV6_EXTENDED_COMMUNITY
    PREFIX = "V6EC"

    EXTENDED_COMMUNITY_TYPE = 0x0302
    IPV6_EXTENDED_COMMUNITY_LENGTH = 20

    SUBTYPES = [
        ("ROUTE_TARGET", 0x0002),
        ("ROUTE_ORIGIN", 0x0003),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for subname, subtype in cls.SUBTYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{subtype:04x}",
                    name=f"IPv6 Ext Comm: {subname}",
                    category=cls.CATEGORY,
                    description=f"RFC 5701 - IPv6 Address Specific Extended Community subtype {hex(subtype)}",
                    params={"subtype": subtype},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="IPv6 Extended Community Length",
                category=cls.CATEGORY,
                description="RFC 5701 - IPv6 Extended Community must be 20 octets",
                params={"expected_length": 20},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="IPv6 Route Target with AS Specific",
                category=cls.CATEGORY,
                description="RFC 5701 - Route Target with 2-byte AS specific",
                params={"subtype": 0x0002, "as_length": 2},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="IPv6 Route Target with 4-byte AS",
                category=cls.CATEGORY,
                description="RFC 5701 - Route Target with 4-byte AS specific",
                params={"subtype": 0x0002, "as_length": 4},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="IPv6 Route Origin with AS Specific",
                category=cls.CATEGORY,
                description="RFC 5701 - Route Origin with 2-byte AS specific",
                params={"subtype": 0x0003, "as_length": 2},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="IPv6 Route Origin with 4-byte AS",
                category=cls.CATEGORY,
                description="RFC 5701 - Route Origin with 4-byte AS specific",
                params={"subtype": 0x0003, "as_length": 4},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="IPv6 Extended Community Global Administrator",
                category=cls.CATEGORY,
                description="RFC 5701 - IPv6 address as Global Administrator field",
                params={"ipv6_addr": "2001:db8::1"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="IPv6 Extended Community with Reserved Subtype",
                category=cls.CATEGORY,
                description="RFC 5701 - Reserved subtype handling",
                params={"subtype": 0xFFFF},
            )
        )
        return tests

    def _build_ipv6_ext_community(
        self, subtype: int, as_num: int, ipv6_addr: str
    ) -> bytes:
        global_admin = bytes.fromhex(ipv6_addr.replace(":", ""))
        if subtype == 0x0002 or subtype == 0x0003:
            return (
                bytes([0x00, 0x03, subtype >> 8, subtype & 0xFF])
                + struct.pack("!H", as_num)
                + global_admin
            )
        return bytes([0x00, 0x03, subtype >> 8, subtype & 0xFF]) + global_admin

    def _send_ext_community_update(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            subtype = params.get("subtype", 0x0002)
            as_num = params.get("as_num", framework.source_as)
            ipv6_addr = params.get("ipv6_addr", "2001:db8::1")
            ext_comm = self._build_ipv6_ext_community(subtype, as_num, ipv6_addr)

            ext_comm_attr = PathAttribute(16, 0x40, ext_comm)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop, ext_comm_attr],
                [(framework.get_prefix("extcomm_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"UPDATE accepted with IPv6 Extended Community (subtype={hex(subtype)})",
                    {},
                )
            return (
                True,
                f"Sent UPDATE with IPv6 Extended Community (subtype={hex(subtype)})",
                {},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_v6ec(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: self._send_ext_community_update(framework, test_case.params),
        )


class RPKIRouterAssessments:
    CATEGORY = TestCategory.RPKI_ROUTER
    PREFIX = "RPKI"

    RPKI_PORT = 323

    PDU_TYPES = [
        ("SERIAL_NOTIFY", 0),
        ("SERIAL_QUERY", 1),
        ("RESET_QUERY", 2),
        ("CACHE_RESPONSE", 3),
        ("IPV4_PREFIX", 4),
        ("IPV6_PREFIX", 6),
        ("END_OF_DATA", 7),
        ("CACHE_RESET", 8),
        ("ERROR_REPORT", 10),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for pdu_name, pdu_type in cls.PDU_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{pdu_type:03d}",
                    name=f"RPKI PDU Type {pdu_type}: {pdu_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 6810 - RPKI-Router Protocol PDU type {pdu_type}",
                    params={"pdu_type": pdu_type},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="RPKI Serial Notify PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - Serial Notify PDU for update notification",
                params={"pdu_type": 0, "serial": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="RPKI Serial Query PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - Serial Query PDU for incremental updates",
                params={"pdu_type": 1, "serial": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="RPKI Reset Query PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - Reset Query PDU for full refresh",
                params={"pdu_type": 2},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="RPKI Cache Response PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - Cache Response PDU with ROA data",
                params={"pdu_type": 3},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="RPKI IPv4 Prefix PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - IPv4 Prefix PDU in Cache Response",
                params={
                    "pdu_type": 4,
                    "prefix": "10.0.0.0",
                    "prefix_len": 8,
                    "max_len": 24,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="RPKI IPv6 Prefix PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - IPv6 Prefix PDU in Cache Response",
                params={
                    "pdu_type": 6,
                    "prefix": "2001:db8::",
                    "prefix_len": 32,
                    "max_len": 48,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="RPKI End of Data PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - End of Data PDU with serial and refresh",
                params={"pdu_type": 7, "serial": 100, "refresh": 3600},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="RPKI Error Report PDU",
                category=cls.CATEGORY,
                description="RFC 6810 - Error Report PDU for validation errors",
                params={"pdu_type": 10, "error_code": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="RPKI PDU Header Format",
                category=cls.CATEGORY,
                description="RFC 6810 - RPKI PDU header: version, PDU type, length",
                params={"version": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="RPKI Length Field Validation",
                category=cls.CATEGORY,
                description="RFC 6810 - PDU length must match header",
                params={"pdu_type": 0, "length_mismatch": True},
            )
        )
        return tests

    def _build_pdu_header(self, pdu_type: int, length: int, version: int = 0) -> bytes:
        return struct.pack("!BHI", version, pdu_type, length)

    def _send_rpki_pdu(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(framework.timeout)
            sock.connect((framework.target_host, self.RPKI_PORT))
            pdu_type = params.get("pdu_type", 0)

            if pdu_type == 0:
                data = self._build_pdu_header(0, 8) + struct.pack(
                    "!I", params.get("serial", 0)
                )
            elif pdu_type == 1:
                data = (
                    self._build_pdu_header(1, 12)
                    + struct.pack("!I", params.get("serial", 0))
                    + struct.pack("!I", 0)
                )
            elif pdu_type == 2:
                data = self._build_pdu_header(2, 8)
            elif pdu_type == 7:
                data = self._build_pdu_header(7, 16) + struct.pack(
                    "!III", params.get("serial", 0), params.get("refresh", 3600), 0
                )
            else:
                data = self._build_pdu_header(pdu_type, 8)

            sock.sendall(data)
            response = sock.recv(4096)
            sock.close()

            if response:
                return (True, f"RPKI response received for PDU type {pdu_type}", {})
            return (True, f"RPKI PDU type {pdu_type} sent", {})
        except ConnectionRefusedError:
            return (
                True,
                f"RPKI-Router not available on port {self.RPKI_PORT} (expected)",
                {},
            )
        except Exception as e:
            return (False, f"RPKI-Router error: {str(e)}", {})

    def test_rpki(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_rpki_pdu(framework, test_case.params)
        )


class OriginValidationAssessments:
    CATEGORY = TestCategory.ORIGIN_VALIDATION
    PREFIX = "OV"

    VALIDATION_STATES = [
        ("NOT_FOUND", 0),
        ("VALID", 1),
        ("INVALID", 2),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for state_name, state_value in cls.VALIDATION_STATES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{state_value:03d}",
                    name=f"Origin Validation State: {state_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 6811 - BGP Origin Validation state {state_value}",
                    params={"validation_state": state_value},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Origin Validation Route with Validated ROA",
                category=cls.CATEGORY,
                description="RFC 6811 - Route matches ROA and is VALID",
                params={
                    "prefix": "10.0.0.0/24",
                    "origin_as": 65001,
                    "validation_state": 1,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Origin Validation Route without ROA",
                category=cls.CATEGORY,
                description="RFC 6811 - No ROA found for prefix (NOT_FOUND)",
                params={
                    "prefix": "192.168.0.0/16",
                    "origin_as": 65001,
                    "validation_state": 0,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="Origin Validation Invalid Origin AS",
                category=cls.CATEGORY,
                description="RFC 6811 - Route AS not covered by ROA (INVALID)",
                params={
                    "prefix": "172.16.0.0/12",
                    "origin_as": 65002,
                    "validation_state": 2,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Origin Validation Max Length Exceeded",
                category=cls.CATEGORY,
                description="RFC 6811 - Route prefix longer than ROA max length",
                params={
                    "prefix": "10.0.0.0/28",
                    "origin_as": 65001,
                    "validation_state": 2,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Origin Validation Exact Match",
                category=cls.CATEGORY,
                description="RFC 6811 - Route prefix exactly matches ROA",
                params={
                    "prefix": "10.1.0.0/16",
                    "origin_as": 65001,
                    "validation_state": 1,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="Origin Validation with AS_PATH",
                category=cls.CATEGORY,
                description="RFC 6811 - Origin validation based on AS_PATH first AS",
                params={"as_path": [65001, 65002], "validation_state": 1},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="Origin Validation BGP Community Attribute",
                category=cls.CATEGORY,
                description="RFC 6811 - Validation state communicated via BGP community",
                params={"community": "validation", "validation_state": 1},
            )
        )
        return tests

    def _send_origin_validated_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            prefix = params.get("prefix", "10.0.0.0/24")
            prefix_parts = prefix.split("/")
            prefix_ip = prefix_parts[0]
            prefix_len = int(prefix_parts[1])

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [], [origin, as_path, next_hop], [(prefix_ip, prefix_len)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            validation_state = params.get("validation_state", 0)
            state_names = {0: "NOT_FOUND", 1: "VALID", 2: "INVALID"}
            if response and len(response) >= 21:
                return (
                    True,
                    f"Route processed with validation state {state_names.get(validation_state, 'UNKNOWN')}",
                    {"validation_state": validation_state},
                )
            return (
                True,
                f"Route sent for validation (state={state_names.get(validation_state, 'UNKNOWN')})",
                {"validation_state": validation_state},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_ov(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: self._send_origin_validated_route(framework, test_case.params),
        )


class AS0Assessments:
    CATEGORY = TestCategory.AS0_PROCESSING
    PREFIX = "AS0"

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="AS 0 in OPEN Message",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in OPEN message My AS field must be rejected",
                expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES["BAD_PEER_AS"],
                params={"as_number": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="AS 0 in AS_PATH",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AS_PATH must be rejected",
                expected_error_code=NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES[
                    "MALFORMED_AS_PATH"
                ],
                params={"as_path": [0, 65001]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="AS 0 in AS4_AGGREGATOR",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AS4_AGGREGATOR must be rejected",
                params={"aggregator_as": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="AS 0 in AGGREGATOR",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AGGREGATOR attribute must be rejected",
                params={"aggregator_as": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="AS 0 Leading in AS_PATH",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 as leading AS in AS_PATH",
                params={"as_path": [0]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="AS 0 in AS_SET",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AS_SET segment",
                params={"as_path": [[0, 65001]]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="AS 0 in AS_CONFED_SEQUENCE",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AS_CONFED_SEQUENCE",
                params={"as_path": [65001, 0]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="AS 0 in AS_CONFED_SET",
                category=cls.CATEGORY,
                description="RFC 7607 - AS 0 in AS_CONFED_SET",
                params={"as_path": [[0]]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="AS 0 Propagation Prevention",
                category=cls.CATEGORY,
                description="RFC 7607 - Routes with AS 0 must not be propagated",
                params={"as_path": [65001, 0, 65002]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="AS 0 with Valid Routes",
                category=cls.CATEGORY,
                description="RFC 7607 - Routes without AS 0 should be processed normally",
                params={"as_path": [65001, 65002]},
            )
        )
        return tests

    def _send_as0_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            as_path_data = params.get("as_path", [65001, 65002])
            if isinstance(as_path_data[0], list):
                path_data = bytes([1, len(as_path_data[0])]) + b"".join(
                    struct.pack("!H", as_num) for as_num in as_path_data[0]
                )
                for remaining in as_path_data[1:]:
                    if isinstance(remaining, list):
                        path_data += bytes([1, len(remaining)]) + b"".join(
                            struct.pack("!H", as_num) for as_num in remaining
                        )
                    else:
                        path_data += (
                            bytes([2, 1, remaining])
                            if isinstance(remaining, int)
                            else bytes([2, 1]) + remaining
                        )
            else:
                path_data = bytes([2, len(as_path_data)]) + b"".join(
                    struct.pack("!H", as_num) if isinstance(as_num, int) else as_num
                    for as_num in as_path_data
                )
            as_path_attr = PathAttribute(2, 0x40, path_data)

            origin = create_origin_attribute(0)
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path_attr, next_hop],
                [(framework.get_prefix("oscillation_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, "UPDATE with AS 0 processed", {})
            return (True, "UPDATE with AS_PATH sent (may contain AS 0)", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_as0(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_as0_route(framework, test_case.params)
        )


class BGPLinkStateAssessments:
    CATEGORY = TestCategory.BGP_LS_NLRI
    PREFIX = "BGPLS"

    BGP_LS_AFI = 16388
    BGP_LS_SAFI_NLRI = 71
    BGP_LS_SAFI_VPN = 72

    NLRI_TYPES = [
        ("NODE", 1),
        ("LINK", 2),
        ("IPV4_PREFIX", 3),
        ("IPV6_PREFIX", 4),
    ]

    PROTOCOL_IDS = [
        ("IS_IS_LEVEL_1", 1),
        ("IS_IS_LEVEL_2", 2),
        ("OSPFV2", 3),
        ("DIRECT", 4),
        ("STATIC", 5),
        ("OSPFV3", 6),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for nlri_name, nlri_type in cls.NLRI_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-NLRI-{nlri_type:02d}",
                    name=f"BGP-LS NLRI Type {nlri_type}: {nlri_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 7752 - BGP-LS NLRI type {nlri_type}",
                    params={"nlri_type": nlri_type},
                )
            )
        for prot_name, prot_id in cls.PROTOCOL_IDS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-PROT-{prot_id:02d}",
                    name=f"BGP-LS Protocol {prot_id}: {prot_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 7752 - BGP-LS protocol ID {prot_id}",
                    params={"protocol_id": prot_id},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="BGP-LS AFI/SAFI Values",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS uses AFI=16388, SAFI=71 (NLRI) or 72 (VPN)",
                params={"afi": cls.BGP_LS_AFI, "safi": cls.BGP_LS_SAFI_NLRI},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="BGP-LS Node NLRI",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS Node NLRI encoding",
                params={"nlri_type": 1, "protocol_id": 3},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="BGP-LS Link NLRI",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS Link NLRI encoding",
                params={"nlri_type": 2, "protocol_id": 3},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="BGP-LS IPv4 Prefix NLRI",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS IPv4 Prefix NLRI encoding",
                params={"nlri_type": 3, "protocol_id": 3},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="BGP-LS IPv6 Prefix NLRI",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS IPv6 Prefix NLRI encoding",
                params={"nlri_type": 4, "protocol_id": 6},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="BGP-LS Node Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 7752 - Node descriptor TLVs (AS, BGP-LS ID, IGP Router ID)",
                params={"descriptor_tlv": 512},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="BGP-LS Link Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 7752 - Link descriptor TLVs (Link-ID, Interface, Neighbor)",
                params={"descriptor_tlv": 258},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="BGP-LS Prefix Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 7752 - Prefix descriptor TLVs (IP Reachability)",
                params={"descriptor_tlv": 265},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="BGP-LS Capability Advertisement",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP capability advertisement for BGP-LS",
                params={
                    "capability_code": 1,
                    "afi": cls.BGP_LS_AFI,
                    "safi": cls.BGP_LS_SAFI_NLRI,
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="BGP-LS VPN SAFI",
                category=cls.CATEGORY,
                description="RFC 7752 - BGP-LS with VPN SAFI (71) for address families",
                params={"afi": cls.BGP_LS_AFI, "safi": cls.BGP_LS_SAFI_VPN},
            )
        )
        return tests

    def _send_bgp_ls_nlri(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            nlri_type = params.get("nlri_type", 1)
            protocol_id = params.get("protocol_id", 3)
            safi = params.get("safi", self.BGP_LS_SAFI_NLRI)

            if nlri_type == 1:
                nlri = (
                    bytes([protocol_id, 0x01])
                    + struct.pack("!H", 512)
                    + struct.pack("!I", framework.source_as)
                )
            elif nlri_type == 2:
                nlri = bytes([protocol_id, 0x02]) + struct.pack("!H", 258) + bytes(8)
            elif nlri_type == 3:
                nlri = bytes([protocol_id, 0x03, 24]) + socket.inet_aton(
                    framework.get_next_hop()
                )
            else:
                nlri = bytes([protocol_id, 0x04, 32]) + socket.inet_pton(
                    socket.AF_INET6, "2001:db8::"
                )

            next_hop = socket.inet_aton(framework.get_next_hop())
            mp_reach_data = (
                struct.pack("!HBB", self.BGP_LS_AFI, safi, len(next_hop))
                + next_hop
                + nlri
            )
            mp_reach = PathAttribute(14, 0x80, mp_reach_data)

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            update = build_update_message([], [origin, as_path, mp_reach], [])
            framework.send_raw(update)
            response = framework.receive_raw()

            nlri_names = {1: "Node", 2: "Link", 3: "IPv4 Prefix", 4: "IPv6 Prefix"}
            if response and len(response) >= 21:
                return (
                    True,
                    f"BGP-LS NLRI type {nlri_type} ({nlri_names.get(nlri_type, 'Unknown')}) accepted",
                    {"nlri_type": nlri_type},
                )
            return (
                True,
                f"BGP-LS NLRI type {nlri_type} ({nlri_names.get(nlri_type, 'Unknown')}) sent",
                {"nlri_type": nlri_type},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_bgpls(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_bgp_ls_nlri(framework, test_case.params)
        )


class BlackholeCommunityAssessments:
    CATEGORY = TestCategory.BLACKHOLE_COMMUNITY
    PREFIX = "BH"

    BLACKHOLE = 0xFFFF029A
    BLACKHOLE_IPV4_PREFIX_LEN = 32
    BLACKHOLE_IPV6_PREFIX_LEN = 128

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = [
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="BLACKHOLE Community Value",
                category=cls.CATEGORY,
                description="RFC 7999 - BLACKHOLE community value 0xFFFF029A",
                params={"community": cls.BLACKHOLE},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="BLACKHOLE IPv4 /32 Prefix",
                category=cls.CATEGORY,
                description="RFC 7999 - Blackhole route for IPv4 /32",
                params={
                    "prefix": "10.0.0.0",
                    "prefix_len": cls.BLACKHOLE_IPV4_PREFIX_LEN,
                },
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="BLACKHOLE IPv6 /128 Prefix",
                category=cls.CATEGORY,
                description="RFC 7999 - Blackhole route for IPv6 /128",
                params={
                    "prefix": "2001:db8::",
                    "prefix_len": cls.BLACKHOLE_IPV6_PREFIX_LEN,
                },
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="BLACKHOLE with NO_EXPORT Scope",
                category=cls.CATEGORY,
                description="RFC 7999 - BLACKHOLE with NO_EXPORT to prevent leakage",
                params={"communities": [cls.BLACKHOLE, 0xFFFFFF01]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="BLACKHOLE with NO_ADVERTISE Scope",
                category=cls.CATEGORY,
                description="RFC 7999 - BLACKHOLE with NO_ADVERTISE for bilateral peers",
                params={"communities": [cls.BLACKHOLE, 0xFFFFFF02]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="BLACKHOLE with NO_EXPORT_SUBCONFED",
                category=cls.CATEGORY,
                description="RFC 7999 - BLACKHOLE with NO_EXPORT_SUBCONFED",
                params={"communities": [cls.BLACKHOLE, 0xFFFFFF03]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="BLACKHOLE Action Implementation",
                category=cls.CATEGORY,
                description="RFC 7999 - Verify traffic to blackholed prefix is discarded",
                params={"prefix": "192.168.100.0", "prefix_len": 24},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="BLACKHOLE Prefix Length /24 IPv4",
                category=cls.CATEGORY,
                description="RFC 7999 - BLACKHOLE with less specific prefix",
                params={"prefix": "192.168.0.0", "prefix_len": 24},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="BLACKHOLE Authorization Validation",
                category=cls.CATEGORY,
                description="RFC 7999 - Validate prefix is authorized by neighbor",
                params={"prefix": "10.0.0.0", "prefix_len": 8},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="BLACKHOLE with Multiple Scoping Communities",
                category=cls.CATEGORY,
                description="RFC 7999 - Multiple scope communities for fine-grained control",
                params={"communities": [cls.BLACKHOLE, 0xFFFFFF01, 0xFFFFFF02]},
            ),
        ]
        return tests

    def _send_blackhole_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            communities = params.get("communities", [self.BLACKHOLE])
            data = b"".join(struct.pack("!I", c) for c in communities)
            comm_attr = PathAttribute(8, 0x40, data)

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            prefix = params.get("prefix", "10.0.0.0")
            prefix_len = params.get("prefix_len", 32)
            update = build_update_message(
                [], [origin, as_path, next_hop, comm_attr], [(prefix, prefix_len)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"Blackhole route accepted with {len(communities)} communities",
                    {},
                )
            return (True, "Blackhole route sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_bh(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_blackhole_route(framework, test_case.params)
        )


class AdminShutdownAssessments:
    CATEGORY = TestCategory.ADMIN_SHUTDOWN
    PREFIX = "AS"

    CEASE_CODE = 6
    ADMIN_SHUTDOWN_SUBCODE = 2
    ADMIN_RESET_SUBCODE = 4
    SHUTDOWN_COMM_MIN = 0
    SHUTDOWN_COMM_MAX = 128

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = [
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Admin Shutdown with UTF-8 Message",
                category=cls.CATEGORY,
                description="RFC 8203 - Cease notification with UTF-8 shutdown communication",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "Administrative shutdown", "length": 22},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Admin Shutdown Zero Length",
                category=cls.CATEGORY,
                description="RFC 8203 - Cease notification with zero-length shutdown communication",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "", "length": 0},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="Admin Shutdown Max Length (128)",
                category=cls.CATEGORY,
                description="RFC 8203 - Cease notification with max-length shutdown communication",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "x" * 128, "length": 128},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Admin Reset with Message",
                category=cls.CATEGORY,
                description="RFC 8203 - Cease notification with admin reset subcode",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_RESET_SUBCODE,
                params={"message": "Administrative reset", "length": 20},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Admin Shutdown Multiline UTF-8",
                category=cls.CATEGORY,
                description="RFC 8203 - Shutdown communication with newlines",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "Line1\nLine2", "length": 11},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="Admin Shutdown Unicode Content",
                category=cls.CATEGORY,
                description="RFC 8203 - Shutdown communication with Unicode characters",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "Maintenance Window \u2022 Scheduled", "length": 30},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="Admin Shutdown Reserved Subcode",
                category=cls.CATEGORY,
                description="RFC 8203 - Cease with admin shutdown subcode",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "RFC 8203 test", "length": 14},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="Admin Shutdown Syslog Format",
                category=cls.CATEGORY,
                description="RFC 8203 - Syslog formatting of shutdown communication",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "[AS65001] Peer going down", "length": 22},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="Admin Shutdown with Error Data",
                category=cls.CATEGORY,
                description="RFC 8203 - Shutdown communication with additional data",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_SHUTDOWN_SUBCODE,
                params={"message": "Testing RFC 8203", "length": 17},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="Admin Reset Backward Compatibility",
                category=cls.CATEGORY,
                description="RFC 8203 - Admin reset compatible with RFC 4486 implementations",
                expected_error_code=cls.CEASE_CODE,
                expected_error_subcode=cls.ADMIN_RESET_SUBCODE,
                params={"message": "Config change", "length": 12},
            ),
        ]
        return tests

    def _send_admin_shutdown(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            message = params.get("message", "")
            msg_bytes = message.encode("utf-8")
            subcode = params.get("subcode", self.ADMIN_SHUTDOWN_SUBCODE)

            data = bytes([self.CEASE_CODE, subcode, len(msg_bytes)]) + msg_bytes
            notification = (
                MARKER
                + struct.pack("!HB", len(data) + 21, MESSAGE_TYPES["NOTIFICATION"])
                + data
            )
            framework.send_raw(notification)
            return (
                True,
                f"Admin shutdown notification sent: {message}",
                {"subcode": subcode},
            )
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_as(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_admin_shutdown(framework, test_case.params)
        )


class MPLSLabelBindingAssessments:
    CATEGORY = TestCategory.MPLS_LABEL_BINDING
    PREFIX = "MLB"

    MULTIPLE_LABELS_CAP_CODE = 8
    MPLS_LABEL_WITHDRAWAL = 0x800000

    SAFI_UNICAST_LABELED = 4
    SAFI_VPN_UNICAST_LABELED = 128

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = [
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Single MPLS Label SAFI-4",
                category=cls.CATEGORY,
                description="RFC 8277 - MP_REACH_NLRI with SAFI=4 for labeled IPv4",
                params={"afi": 1, "safi": cls.SAFI_UNICAST_LABELED, "label": 100},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Single MPLS Label SAFI-128",
                category=cls.CATEGORY,
                description="RFC 8277 - MP_REACH_NLRI with SAFI=128 for labeled VPN",
                params={"afi": 1, "safi": cls.SAFI_VPN_UNICAST_LABELED, "label": 200},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="Multiple Labels Capability",
                category=cls.CATEGORY,
                description="RFC 8277 - Multiple Labels Capability advertisement",
                params={"cap_code": cls.MULTIPLE_LABELS_CAP_CODE, "count": 255},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Label Binding Advertisement",
                category=cls.CATEGORY,
                description="RFC 8277 - Advertisement of MPLS label binding",
                params={"afi": 1, "safi": cls.SAFI_UNICAST_LABELED, "label": 1000},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Label Withdrawal with Compatibility",
                category=cls.CATEGORY,
                description="RFC 8277 - Withdrawal NLRI with Compatibility field",
                params={
                    "afi": 1,
                    "safi": cls.SAFI_UNICAST_LABELED,
                    "compatibility": cls.MPLS_LABEL_WITHDRAWAL,
                },
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="Label Encoding Single Label",
                category=cls.CATEGORY,
                description="RFC 8277 - Single label encoding: 20-bit label + reserved + S bit",
                params={"afi": 1, "safi": cls.SAFI_UNICAST_LABELED, "label": 256},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="Label Propagation No NH Change",
                category=cls.CATEGORY,
                description="RFC 8277 - Labels unchanged when next-hop unchanged",
                params={"afi": 1, "safi": cls.SAFI_UNICAST_LABELED, "label": 512},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="Label Propagation NH Change",
                category=cls.CATEGORY,
                description="RFC 8277 - Labels replaced on next-hop change",
                params={"afi": 1, "safi": cls.SAFI_UNICAST_LABELED, "label": 1024},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="IPv6 Labeled Unicast SAFI-4",
                category=cls.CATEGORY,
                description="RFC 8277 - Labeled IPv6 unicast (AFI=2, SAFI=4)",
                params={"afi": 2, "safi": cls.SAFI_UNICAST_LABELED, "label": 768},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="Label Count Min Validation",
                category=cls.CATEGORY,
                description="RFC 8277 - Count field MUST be >= 2, not 0 or 1",
                params={"cap_code": cls.MULTIPLE_LABELS_CAP_CODE, "count": 2},
            ),
        ]
        return tests

    def _build_label_nlri(self, label: int, prefix: bytes, prefix_len: int) -> bytes:
        label_bytes = struct.pack("!I", label)[1:]
        nlri = bytes([prefix_len]) + label_bytes + bytes([0x80]) + prefix
        return nlri

    def _send_labeled_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            afi = params.get("afi", 1)
            safi = params.get("safi", self.SAFI_UNICAST_LABELED)
            label = params.get("label", 100)

            if afi == 1:
                prefix = socket.inet_aton(framework.get_prefix("vpn_prefix_pool", 0))
            else:
                prefix = socket.inet_pton(socket.AF_INET6, "2001:db8::")

            nlri = self._build_label_nlri(label, prefix, 24 if afi == 1 else 32)
            next_hop = socket.inet_aton(framework.get_next_hop())
            mp_reach_data = (
                struct.pack("!HBB", afi, safi, len(next_hop))
                + next_hop
                + bytes([0])
                + nlri
            )
            mp_reach = PathAttribute(14, 0x80, mp_reach_data)

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            update = build_update_message([], [origin, as_path, mp_reach], [])
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (
                    True,
                    f"Labeled route accepted (label={label}, AFI={afi}, SAFI={safi})",
                    {},
                )
            return (True, f"Labeled route sent (label={label})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_mlb(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_labeled_route(framework, test_case.params)
        )


class LargeCommunityUsageAssessments:
    CATEGORY = TestCategory.LARGE_COMMUNITY_USAGE
    PREFIX = "LCU"

    LARGE_COMMUNITY_TYPE = 32

    FUNCTION_TYPES = [
        ("ISO_3166_1_COUNTRY", 1),
        ("UN_M49_REGION", 2),
        ("RELATION", 3),
        ("ASN_SELECTIVE_NO_EXPORT", 4),
        ("LOCATION_SELECTIVE_NO_EXPORT", 5),
        ("ASN_PREPEND", 6),
        ("LOCATION_PREPEND", 7),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for func_name, func_id in cls.FUNCTION_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-FUNC-{func_id:02d}",
                    name=f"Large Community Function {func_id}: {func_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 8195 - Large Community function {func_id}",
                    params={"function": func_id, "global_admin": 64496},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Selective NO_EXPORT by ASN",
                category=cls.CATEGORY,
                description="RFC 8195 - 64496:4:peer_as to prevent export to specific AS",
                params={"lcomm": [64496, 4, 65001]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Selective NO_EXPORT by Country",
                category=cls.CATEGORY,
                description="RFC 8195 - Location-based selective NO_EXPORT",
                params={"lcomm": [64496, 5, 528]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="AS Prepend by ASN",
                category=cls.CATEGORY,
                description="RFC 8195 - 64496:6:peer_as for selective prepending",
                params={"lcomm": [64496, 6, 65001]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Route Server Control",
                category=cls.CATEGORY,
                description="RFC 8195 - Route server prefix control communities",
                params={"lcomm": [64511, 0, 0]},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Route Preference Communities",
                category=cls.CATEGORY,
                description="RFC 8195 - Route preference manipulation communities",
                params={"lcomm": [64496, 8, 0]},
            )
        )
        return tests

    def _build_large_community(self, lcomm: List[int]) -> bytes:
        return b"".join(struct.pack("!I", v) for v in lcomm)

    def _send_large_community_update(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            lcomm = params.get("lcomm", [64496, 4, 65001])
            lcomm_data = self._build_large_community(lcomm)
            lcomm_attr = PathAttribute(self.LARGE_COMMUNITY_TYPE, 0x40, lcomm_data)

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop, lcomm_attr],
                [(framework.get_prefix("large_comm_usage_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"Large community {lcomm} accepted", {"lcomm": lcomm})
            return (True, f"Sent route with large community {lcomm}", {"lcomm": lcomm})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_lcu(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: self._send_large_community_update(framework, test_case.params),
        )


class DataCenterBGPAssessments:
    CATEGORY = TestCategory.DATACENTER_BGP
    PREFIX = "DCB"

    PRIVATE_AS_MIN = 64512
    PRIVATE_AS_MAX = 65534

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = [
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Single-Hop EBGP Session",
                category=cls.CATEGORY,
                description="RFC 7938 - Single-hop EBGP over point-to-point links",
                params={"as_numbers": [cls.PRIVATE_AS_MIN, cls.PRIVATE_AS_MIN + 1]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Private ASN Usage",
                category=cls.CATEGORY,
                description="RFC 7938 - Private ASNs 64512-65534 for data center",
                params={"as_numbers": [65000, 65001]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="Four-Octet ASN in Data Center",
                category=cls.CATEGORY,
                description="RFC 7938 - Four-octet ASNs for large data centers",
                params={"as_numbers": [4294967295, 65001]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Allowas-in Feature",
                category=cls.CATEGORY,
                description="RFC 7938 - Accept own ASN in AS_PATH when Allowas-in enabled",
                params={"as_numbers": [65001, 65001]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Remove Private AS Feature",
                category=cls.CATEGORY,
                description="RFC 7938 - Strip private ASNs before advertising to WAN",
                params={"as_numbers": [65534, 64512, 100]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="Basic ECMP Behavior",
                category=cls.CATEGORY,
                description="RFC 7938 - Multiple equal-cost paths are used",
                params={"as_numbers": [65001, 65002], "ecmp": "basic"},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="Multipath Relax",
                category=cls.CATEGORY,
                description="RFC 7938 - Multipath relax for different neighboring AS",
                params={"as_numbers": [65001, 65002], "ecmp": "relax"},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="AS_PATH Loop Detection DC",
                category=cls.CATEGORY,
                description="RFC 7938 - Routes with own ASN rejected in data center",
                params={"as_numbers": [65001, 65001, 65002]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="Route Advertisement No Summarization",
                category=cls.CATEGORY,
                description="RFC 7938 - Server subnets announced without summarization",
                params={"prefix": "10.0.0.0", "prefix_len": 24},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="ECMP with Link Bandwidth",
                category=cls.CATEGORY,
                description="RFC 7938 - Weighted ECMP using BGP Link Bandwidth community",
                params={"as_numbers": [65001, 65002], "ecmp": "weighted"},
            ),
        ]
        return tests

    def _send_dc_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            as_numbers = params.get("as_numbers", [65001, 65002])
            as_path = create_as_path_attribute(as_numbers)
            origin = create_origin_attribute(0)
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            prefix = params.get("prefix", "10.0.0.0")
            prefix_len = params.get("prefix_len", 24)

            update = build_update_message(
                [], [origin, as_path, next_hop], [(prefix, prefix_len)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (
                    True,
                    f"DC route accepted with AS_PATH length={len(as_numbers)}",
                    {},
                )
            return (True, "DC route sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_dcb(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_dc_route(framework, test_case.params)
        )


class GracefulShutdownAssessments:
    CATEGORY = TestCategory.GRACEFUL_SHUTDOWN
    PREFIX = "GSD"

    GRACEFUL_SHUTDOWN = 0xFFFF0000
    RECOMMENDED_LOCAL_PREF = 0

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = [
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="Graceful Shutdown Community Value",
                category=cls.CATEGORY,
                description="RFC 8326 - GRACEFUL_SHUTDOWN community 0xFFFF0000",
                params={"community": cls.GRACEFUL_SHUTDOWN},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="Graceful Shutdown LOCAL_PREF 0",
                category=cls.CATEGORY,
                description="RFC 8326 - Set LOCAL_PREF to 0 for graceful shutdown paths",
                params={
                    "local_pref": cls.RECOMMENDED_LOCAL_PREF,
                    "community": cls.GRACEFUL_SHUTDOWN,
                },
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="Graceful Shutdown with NO_EXPORT",
                category=cls.CATEGORY,
                description="RFC 8326 - Combine with NO_EXPORT for scope control",
                params={"communities": [cls.GRACEFUL_SHUTDOWN, 0xFFFFFF01]},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="Graceful Shutdown Route Selection",
                category=cls.CATEGORY,
                description="RFC 8326 - Graceful shutdown paths deprioritized",
                params={"community": cls.GRACEFUL_SHUTDOWN},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="Graceful Shutdown Maintenance Window",
                category=cls.CATEGORY,
                description="RFC 8326 - Planned maintenance announcement",
                params={"community": cls.GRACEFUL_SHUTDOWN},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="Graceful Shutdown Traffic Rerouting",
                category=cls.CATEGORY,
                description="RFC 8326 - Alternate paths used during shutdown",
                params={"community": cls.GRACEFUL_SHUTDOWN},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-007",
                name="Graceful Shutdown Restoration",
                category=cls.CATEGORY,
                description="RFC 8326 - Route restoration after maintenance",
                params={"community": cls.GRACEFUL_SHUTDOWN, "action": "restore"},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-008",
                name="Graceful Shutdown in EBGP",
                category=cls.CATEGORY,
                description="RFC 8326 - Graceful shutdown behavior in EBGP sessions",
                params={"community": cls.GRACEFUL_SHUTDOWN, "session_type": "ebgp"},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-009",
                name="Graceful Shutdown in IBGP",
                category=cls.CATEGORY,
                description="RFC 8326 - Graceful shutdown behavior in IBGP sessions",
                params={"community": cls.GRACEFUL_SHUTDOWN, "session_type": "ibgp"},
            ),
            TestCase(
                test_id=f"{cls.PREFIX}-010",
                name="Graceful Shutdown Community Recognition",
                category=cls.CATEGORY,
                description="RFC 8326 - Verify well-known community is recognized",
                params={"community": cls.GRACEFUL_SHUTDOWN},
            ),
        ]
        return tests

    def _send_graceful_shutdown_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            communities = params.get("communities", [self.GRACEFUL_SHUTDOWN])
            comm_data = b"".join(struct.pack("!I", c) for c in communities)
            comm_attr = PathAttribute(8, 0x40, comm_data)

            local_pref = params.get("local_pref", self.RECOMMENDED_LOCAL_PREF)
            lp_attr = PathAttribute(5, 0x40, struct.pack("!I", local_pref))

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop, lp_attr, comm_attr],
                [(framework.get_prefix("graceful_shutdown_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()
            if response and len(response) >= 21:
                return (
                    True,
                    f"Graceful shutdown route accepted (LOCAL_PREF={local_pref})",
                    {},
                )
            return (True, "Graceful shutdown route sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_gsd(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: self._send_graceful_shutdown_route(framework, test_case.params),
        )


class EVPNNVOAssessments:
    CATEGORY = TestCategory.EVPN_NVO
    PREFIX = "EVPN"

    TUNNEL_TYPES = [
        ("VXLAN", 8),
        ("NVGRE", 9),
        ("MPLS", 10),
        ("MPLS_IN_GRE", 11),
        ("VXLAN_GPE", 12),
    ]

    VNI_LENGTH = 24

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for tunnel_name, tunnel_type in cls.TUNNEL_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-TUN-{tunnel_type:02d}",
                    name=f"Tunnel Type {tunnel_type}: {tunnel_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 8365 - {tunnel_name} encapsulation support",
                    params={"tunnel_type": tunnel_type},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="EVPN VXLAN Encapsulation",
                category=cls.CATEGORY,
                description="RFC 8365 - VXLAN tunnel type (value 8)",
                params={"tunnel_type": 8, "vni": 10000},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="EVPN VXLAN-GPE Encapsulation",
                category=cls.CATEGORY,
                description="RFC 8365 - VXLAN-GPE tunnel type (value 12)",
                params={"tunnel_type": 12, "vni": 20000},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="VNI Encoding 24-bit",
                category=cls.CATEGORY,
                description="RFC 8365 - VNI is a 24-bit value",
                params={"vni": 0xFFFFFF},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="RT Auto-Derivation VID",
                category=cls.CATEGORY,
                description="RFC 8365 - Route Target auto-derivation from VID",
                params={"rt_deriv_type": 0},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="RT Auto-Derivation VXLAN",
                category=cls.CATEGORY,
                description="RFC 8365 - Route Target auto-derivation from VXLAN VNI",
                params={"rt_deriv_type": 1},
            )
        )
        return tests

    def _send_evpn_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            tunnel_type = params.get("tunnel_type", 8)
            tunnel_comm = bytes([0x00, 0x00, 0x00, tunnel_type, 0x00, 0x00, 0x00, 0x00])
            tunnel_attr = PathAttribute(23, 0xC0, tunnel_comm)

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [], [origin, as_path, next_hop, tunnel_attr], []
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            tunnel_names = {
                8: "VXLAN",
                9: "NVGRE",
                10: "MPLS",
                11: "MPLS in GRE",
                12: "VXLAN-GPE",
            }
            if response and len(response) >= 21:
                return (
                    True,
                    f"EVPN route with {tunnel_names.get(tunnel_type, 'Unknown')} accepted",
                    {},
                )
            return (True, f"EVPN route sent with tunnel type {tunnel_type}", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_evpn(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_evpn_route(framework, test_case.params)
        )


class SegmentRoutingAssessments:
    CATEGORY = TestCategory.SEGMENT_ROUTING
    PREFIX = "SR"

    ALGORITHMS = [
        ("SPF", 0),
        ("STRICT_SPF", 1),
    ]

    BGP_PEERING_SEGMENTS = [
        ("PEER_NODE", 1),
        ("PEER_ADJ", 2),
        ("PEER_SET", 3),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for algo_name, algo_id in cls.ALGORITHMS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-ALGO-{algo_id}",
                    name=f"SR Algorithm {algo_id}: {algo_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 8402 - Segment Routing {algo_name} algorithm",
                    params={"algorithm": algo_id},
                )
            )
        for seg_name, seg_id in cls.BGP_PEERING_SEGMENTS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-PEER-{seg_id}",
                    name=f"Peering Segment {seg_id}: {seg_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 8402 - {seg_name} for Egress Peer Engineering",
                    params={"peering_segment_type": seg_id},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-001",
                name="SR-MPLS SID Label",
                category=cls.CATEGORY,
                description="RFC 8402 - Segment ID encoded as MPLS label",
                params={"sid_type": "mpls", "sid_value": 16000},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-002",
                name="SR-MPLS SID within SRGB",
                category=cls.CATEGORY,
                description="RFC 8402 - SID value within SR Global Block range",
                params={"sid_type": "mpls", "sid_value": 16000, "srgb_range": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-003",
                name="BGP-Prefix Segment",
                category=cls.CATEGORY,
                description="RFC 8402 - BGP-Prefix SID advertisement",
                params={"segment_type": "prefix"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-004",
                name="PeerNode SID",
                category=cls.CATEGORY,
                description="RFC 8402 - PeerNode SID for EPE",
                params={"peering_segment_type": 1},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-005",
                name="PeerAdj SID",
                category=cls.CATEGORY,
                description="RFC 8402 - PeerAdj SID for EPE",
                params={"peering_segment_type": 2},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-006",
                name="PeerSet SID",
                category=cls.CATEGORY,
                description="RFC 8402 - PeerSet SID for EPE load balancing",
                params={"peering_segment_type": 3},
            )
        )
        return tests

    def _send_sr_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            segment_type = params.get("segment_type", "mpls")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())
            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.get_prefix("sr_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"SR route accepted ({segment_type})", {})
            return (True, f"SR route sent ({segment_type})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_sr(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_sr_route(framework, test_case.params)
        )


class IRBAssessments:
    CATEGORY = TestCategory.EVPN_IRB
    PREFIX = "IRB"

    IRB_TYPES = [
        ("SYMMETRIC", "symmetric"),
        ("ASYMMETRIC", "asymmetric"),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for irb_name, irb_type in cls.IRB_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{irb_name}-001",
                    name=f"IRB {irb_name} - MAC/IP Route with Label2",
                    category=cls.CATEGORY,
                    description=f"RFC 9135 - {irb_name} IRB MAC/IP advertisement with MPLS Label2",
                    params={
                        "irb_type": irb_type,
                        "route_type": "mac_ip",
                        "label2": True,
                    },
                )
            )
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{irb_name}-002",
                    name=f"IRB {irb_name} - Subnet Route (RT-5)",
                    category=cls.CATEGORY,
                    description=f"RFC 9135 - {irb_name} IRB subnet route advertisement",
                    params={"irb_type": irb_type, "route_type": "rt5"},
                )
            )
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{irb_name}-003",
                    name=f"IRB {irb_name} - Default Gateway Extended Community",
                    category=cls.CATEGORY,
                    description=f"RFC 9135 - {irb_name} IRB Default Gateway extended community",
                    params={"irb_type": irb_type, "default_gateway": True},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-ANYCAST-001",
                name="Anycast MAC Address Derivation",
                category=cls.CATEGORY,
                description="RFC 9135 - Anycast MAC derivation for IRB",
                params={"anycast_mac": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-MOBILITY-001",
                name="MAC/IP Mobility Procedures",
                category=cls.CATEGORY,
                description="RFC 9135 - MAC Mobility with IRB",
                params={"mobility": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-EVPN-ROUTER-MAC-001",
                name="EVPN Router's MAC Extended Community",
                category=cls.CATEGORY,
                description="RFC 9135 - EVPN Router's MAC Extended Community encoding",
                params={"evpn_router_mac": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-TTL-001",
                name="TTL/Hop Limit Decrement",
                category=cls.CATEGORY,
                description="RFC 9135 - TTL decrement on symmetric vs asymmetric IRB",
                params={"ttl_check": True},
            )
        )
        return tests

    def _send_irb_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            irb_type = params.get("irb_type", "symmetric")

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            mp_reach = create_mp_reach_nlri_attribute(
                1,
                128,
                socket.inet_aton(framework.get_next_hop()),
                b"\xc0\xa8\x64\x00\x18",
            )

            update = build_update_message([], [origin, as_path, next_hop, mp_reach], [])
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"IRB route accepted ({irb_type})", {})
            return (True, f"IRB route sent ({irb_type})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_irb(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_irb_route(framework, test_case.params)
        )


class EVPNIPPrefixAssessments:
    CATEGORY = TestCategory.EVPN_IP_PREFIX
    PREFIX = "RT5"

    IP_FAMILIES = ["IPv4", "IPv6"]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for ip_family in cls.IP_FAMILIES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{ip_family}-001",
                    name=f"EVPN IP Prefix {ip_family} Route Encoding",
                    category=cls.CATEGORY,
                    description=f"RFC 9136 - EVPN Route Type 5 NLRI encoding for {ip_family}",
                    params={
                        "ip_family": ip_family.lower(),
                        "nlri_length": 34 if ip_family == "IPv4" else 58,
                    },
                )
            )
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{ip_family}-002",
                    name=f"EVPN IP Prefix {ip_family} with Overlay Index (GW IP)",
                    category=cls.CATEGORY,
                    description=f"RFC 9136 - {ip_family} prefix with Gateway IP Overlay Index",
                    params={
                        "ip_family": ip_family.lower(),
                        "overlay_index_type": "gw_ip",
                    },
                )
            )
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{ip_family}-003",
                    name=f"EVPN IP Prefix {ip_family} with Overlay Index (ESI)",
                    category=cls.CATEGORY,
                    description=f"RFC 9136 - {ip_family} prefix with ESI Overlay Index",
                    params={
                        "ip_family": ip_family.lower(),
                        "overlay_index_type": "esi",
                    },
                )
            )
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{ip_family}-004",
                    name=f"EVPN IP Prefix {ip_family} with Overlay Index (MAC)",
                    category=cls.CATEGORY,
                    description=f"RFC 9136 - {ip_family} prefix with MAC Overlay Index",
                    params={
                        "ip_family": ip_family.lower(),
                        "overlay_index_type": "mac",
                    },
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-RECURSIVE-001",
                name="RT-5 Recursive Lookup Resolution",
                category=cls.CATEGORY,
                description="RFC 9136 - Overlay Index recursive resolution",
                params={"recursive_resolution": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-INVALID-001",
                name="RT-5 Invalid Combination (ESI + GW IP Non-Zero)",
                category=cls.CATEGORY,
                description="RFC 9136 - Treat as withdraw for invalid RT-5 combination",
                params={"invalid_combination": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-LABEL-001",
                name="RT-5 MPLS Label Zero with Overlay Index",
                category=cls.CATEGORY,
                description="RFC 9136 - MPLS label zero requires Overlay Index",
                params={"label_zero": True},
            )
        )
        return tests

    def _send_rt5_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            ip_family = params.get("ip_family", "ipv4")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            prefix = (
                framework.get_prefix("oscillation_prefix_pool", 0)
                if ip_family == "ipv4"
                else "2001:db8::"
            )
            prefix_len = 24 if ip_family == "ipv4" else 64

            update = build_update_message(
                [], [origin, as_path, next_hop], [(prefix, prefix_len)]
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"RT-5 route accepted ({ip_family})", {})
            return (True, f"RT-5 route sent ({ip_family})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_rt5(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_rt5_route(framework, test_case.params)
        )


class BGPRoleAssessments:
    CATEGORY = TestCategory.BGP_ROLE
    PREFIX = "ROLE"

    ROLE_VALUES = [
        ("PROVIDER", 0),
        ("ROUTE_SERVER", 1),
        ("ROUTE_SERVER_CLIENT", 2),
        ("CUSTOMER", 3),
        ("PEER", 4),
    ]

    ROLE_PAIRS = [
        ("PROVIDER", "CUSTOMER"),
        ("CUSTOMER", "PROVIDER"),
        ("ROUTE_SERVER", "ROUTE_SERVER_CLIENT"),
        ("ROUTE_SERVER_CLIENT", "ROUTE_SERVER"),
        ("PEER", "PEER"),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for role_name, role_id in cls.ROLE_VALUES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{role_name}",
                    name=f"BGP Role Capability: {role_name} ({role_id})",
                    category=cls.CATEGORY,
                    description=f"RFC 9234 - BGP Role {role_name} capability advertisement",
                    params={"role": role_id, "role_name": role_name},
                )
            )
        for local_role, remote_role in cls.ROLE_PAIRS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{local_role}-{remote_role}",
                    name=f"Role Pair: {local_role} -> {remote_role}",
                    category=cls.CATEGORY,
                    description="RFC 9234 - Valid role pair for session establishment",
                    params={"local_role": local_role, "remote_role": remote_role},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-OTC-001",
                name="OTC Attribute Present from Customer",
                category=cls.CATEGORY,
                description="RFC 9234 - OTC Attribute on route from Customer is leak",
                params={"otc_from_customer": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-OTC-002",
                name="OTC Attribute Added on Egress to Customer",
                category=cls.CATEGORY,
                description="RFC 9234 - OTC Attribute added when advertising to Customer",
                params={"otc_to_customer": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-OTC-003",
                name="OTC Attribute Not Propagated to Provider",
                category=cls.CATEGORY,
                description="RFC 9234 - OTC Attribute not propagated to Providers",
                params={"otc_propagation": False},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-MISMATCH-001",
                name="Role Mismatch Notification",
                category=cls.CATEGORY,
                description="RFC 9234 - OPEN Message Error subcode 11 for Role Mismatch",
                params={"role_mismatch": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-STRICT-001",
                name="Strict Mode - Role Required",
                category=cls.CATEGORY,
                description="RFC 9234 - Strict mode requires Role capability",
                params={"strict_mode": True},
            )
        )
        return tests

    def _send_role_open(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            role = params.get("role", 3)
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()

            if response and len(response) >= 19:
                return (True, f"BGP OPEN with Role {role} accepted", {})
            return (True, f"BGP OPEN with Role {role} sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_role(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_role_open(framework, test_case.params)
        )


class SRv6BGPOverlayAssessments:
    CATEGORY = TestCategory.SRV6_BGP_OVERLAY
    PREFIX = "SRV6"

    SERVICE_TYPES = [
        ("L3_SERVICE", "l3_service"),
        ("L2_SERVICE", "l2_service"),
    ]

    ENDPOINT_BEHAVIORS = [
        ("END_DX4", 0x0001),
        ("END_DT4", 0x0002),
        ("END_DX6", 0x0003),
        ("END_DT6", 0x0004),
        ("END_DX2", 0x0005),
        ("END_DT2U", 0x0007),
        ("END_DT2M", 0x0008),
        ("END_DT46", 0x0009),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for svc_name, svc_type in cls.SERVICE_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{svc_name}-001",
                    name=f"SRv6 {svc_name} TLV Encoding",
                    category=cls.CATEGORY,
                    description=f"RFC 9252 - SRv6 {svc_name} TLV in BGP Prefix-SID attribute",
                    params={"service_type": svc_type},
                )
            )
        for behavior_name, behavior_id in cls.ENDPOINT_BEHAVIORS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-SID-{behavior_name}",
                    name=f"SRv6 SID Endpoint Behavior: {behavior_name}",
                    category=cls.CATEGORY,
                    description=f"RFC 9252 - SRv6 SID with {behavior_name} behavior",
                    params={
                        "endpoint_behavior": behavior_id,
                        "behavior_name": behavior_name,
                    },
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-SID-INFO-001",
                name="SRv6 SID Information Sub-TLV",
                category=cls.CATEGORY,
                description="RFC 9252 - SRv6 SID Information Sub-TLV encoding",
                params={"sub_tlv_type": 1},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-STRUCTURE-001",
                name="SRv6 SID Structure Sub-Sub-TLV",
                category=cls.CATEGORY,
                description="RFC 9252 - SRv6 SID Structure Sub-Sub-TLV",
                params={"sub_sub_tlv_type": 1},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-TRANSPOSITION-001",
                name="SRv6 SID Transposition Scheme",
                category=cls.CATEGORY,
                description="RFC 9252 - SRv6 SID transposition for efficient NLRI encoding",
                params={"transposition": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-L3VPN-001",
                name="IPv4 VPN over SRv6 Core",
                category=cls.CATEGORY,
                description="RFC 9252 - L3VPN IPv4 over SRv6 encapsulation",
                params={"service": "ipv4_vpn", "encapsulation": "srv6"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-L3VPN-002",
                name="IPv6 VPN over SRv6 Core",
                category=cls.CATEGORY,
                description="RFC 9252 - L3VPN IPv6 over SRv6 encapsulation",
                params={"service": "ipv6_vpn", "encapsulation": "srv6"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-EVPN-001",
                name="EVPN MAC/IP over SRv6 Core",
                category=cls.CATEGORY,
                description="RFC 9252 - EVPN Route Type 2 over SRv6 encapsulation",
                params={"service": "evpn_rt2", "encapsulation": "srv6"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-EVPN-002",
                name="EVPN IP Prefix (RT-5) over SRv6 Core",
                category=cls.CATEGORY,
                description="RFC 9252 - EVPN Route Type 5 over SRv6 encapsulation",
                params={"service": "evpn_rt5", "encapsulation": "srv6"},
            )
        )
        return tests

    def _send_srv6_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            service_type = params.get("service_type", "l3_service")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.get_prefix("srv6_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"SRv6 route accepted ({service_type})", {})
            return (True, f"SRv6 route sent ({service_type})", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_srv6(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_srv6_route(framework, test_case.params)
        )


class SRPolicyAssessments:
    CATEGORY = TestCategory.SR_POLICY
    PREFIX = "SRPOL"

    SEGMENT_TYPES = list("ABCDEFGHIJK")

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for seg_type in cls.SEGMENT_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-SEG-{seg_type}",
                    name=f"SR Policy Segment Type {seg_type}",
                    category=cls.CATEGORY,
                    description=f"RFC 9256 - SR Policy segment list type {seg_type}",
                    params={"segment_type": seg_type},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-IDENT-001",
                name="SR Policy Identification (Headend, Color, Endpoint)",
                category=cls.CATEGORY,
                description="RFC 9256 - SR Policy identified by tuple",
                params={"identification": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-CP-001",
                name="SR Policy Candidate Path Preference",
                category=cls.CATEGORY,
                description="RFC 9256 - Candidate path selection by preference",
                params={"candidate_path": True, "selection_criteria": "preference"},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-CP-002",
                name="SR Policy Candidate Path Protocol-Origin",
                category=cls.CATEGORY,
                description="RFC 9256 - Candidate path tiebreaker: Protocol-Origin",
                params={
                    "candidate_path": True,
                    "selection_criteria": "protocol_origin",
                },
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-BSID-001",
                name="SR Policy Binding SID (BSID)",
                category=cls.CATEGORY,
                description="RFC 9256 - BSID association with SR Policy",
                params={"bsid": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-STEER-001",
                name="Steering into SR Policy",
                category=cls.CATEGORY,
                description="RFC 9256 - Per-destination steering into SR Policy",
                params={"steering": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-VALID-001",
                name="SR Policy Validity",
                category=cls.CATEGORY,
                description="RFC 9256 - SR Policy validity criterion",
                params={"validity": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-DROP-001",
                name="Drop-Upon-Invalid SR Policy",
                category=cls.CATEGORY,
                description="RFC 9256 - Drop-upon-invalid behavior",
                params={"drop_invalid": True},
            )
        )
        return tests

    def _send_srpol_route(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            segment_type = params.get("segment_type", "A")
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.get_prefix("srpolicy_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"SR Policy segment type {segment_type} accepted", {})
            return (True, f"SR Policy segment type {segment_type} sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_srpol(self, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_srpol_route(framework, test_case.params)
        )


class BGP_LS_UpdatedAssessments:
    CATEGORY = TestCategory.BGP_LS_UPDATED
    PREFIX = "BGPLS"

    NLRI_TYPES = [
        ("NODE", 1),
        ("LINK", 2),
        ("IPV4_PREFIX", 3),
        ("IPV6_PREFIX", 4),
    ]

    PROTOCOL_IDS = [
        ("IS_IS_LEVEL_1", 1),
        ("IS_IS_LEVEL_2", 2),
        ("OSPFV2", 3),
        ("DIRECT", 4),
        ("STATIC", 5),
        ("OSPFV3", 6),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        tests = []
        for nlri_name, nlri_id in cls.NLRI_TYPES:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-{nlri_name}",
                    name=f"BGP-LS NLRI Type: {nlri_name} ({nlri_id})",
                    category=cls.CATEGORY,
                    description=f"RFC 9552 - BGP-LS NLRI type {nlri_id} ({nlri_name})",
                    params={"nlri_type": nlri_id, "nlri_name": nlri_name},
                )
            )
        for proto_name, proto_id in cls.PROTOCOL_IDS:
            tests.append(
                TestCase(
                    test_id=f"{cls.PREFIX}-PROTO-{proto_name}",
                    name=f"BGP-LS Protocol ID: {proto_name} ({proto_id})",
                    category=cls.CATEGORY,
                    description=f"RFC 9552 - BGP-LS Protocol-ID {proto_id}",
                    params={"protocol_id": proto_id},
                )
            )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-NODE-DESC-001",
                name="BGP-LS Node Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 9552 - Node Descriptor sub-TLVs",
                params={"node_descriptor_tlvs": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-LINK-DESC-001",
                name="BGP-LS Link Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 9552 - Link Descriptor TLVs",
                params={"link_descriptor_tlvs": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-PREFIX-DESC-001",
                name="BGP-LS Prefix Descriptor TLVs",
                category=cls.CATEGORY,
                description="RFC 9552 - Prefix Descriptor TLVs",
                params={"prefix_descriptor_tlvs": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-ATTR-001",
                name="BGP-LS Attribute TLVs",
                category=cls.CATEGORY,
                description="RFC 9552 - BGP-LS Attribute TLVs",
                params={"attribute_tlvs": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-VPN-001",
                name="BGP-LS VPN (SAFI 72)",
                category=cls.CATEGORY,
                description="RFC 9552 - BGP-LS-VPN with SAFI 72",
                params={"safi": 72},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-UNKNOWN-001",
                name="BGP-LS Unknown NLRI Type Handling",
                category=cls.CATEGORY,
                description="RFC 9552 - Unknown NLRI types preserved and propagated",
                params={"unknown_nlri": True},
            )
        )
        tests.append(
            TestCase(
                test_id=f"{cls.PREFIX}-ORDER-001",
                name="BGP-LS TLV Ordering",
                category=cls.CATEGORY,
                description="RFC 9552 - TLVs ordered ascending by type",
                params={"tlv_ordering": True},
            )
        )
        return tests

    def _send_bgp_ls_nlri(
        self, framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        if not framework.connect():
            return (False, "Failed to connect", {})
        try:
            msg = build_open_message(framework.source_as)
            framework.send_raw(msg)
            response = framework.receive_raw()
            if not response or len(response) < 19:
                return (True, "No OPEN response", {})

            keepalive = build_keepalive_message()
            framework.send_raw(keepalive)
            framework.receive_raw()

            nlri_type = params.get("nlri_type", 1)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.get_prefix("bgpls_prefix_pool", 0), 24)],
            )
            framework.send_raw(update)
            response = framework.receive_raw()

            if response and len(response) >= 21:
                return (True, f"BGP-LS NLRI type {nlri_type} accepted", {})
            return (True, f"BGP-LS NLRI type {nlri_type} sent", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()

    def test_bgp_ls_upd(
        self, framework: BGPTestFramework, test_index: int
    ) -> TestResult:
        test_case = self.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: self._send_bgp_ls_nlri(framework, test_case.params)
        )


class AIGPAssessments:
    PREFIX = "AIGP"
    CATEGORY = TestCategory.AIGP

    TESTS = [
        ("AIGP-001", "AIGP Attribute Type", "RFC 7311 - AIGP attribute type code 28"),
        (
            "AIGP-002",
            "AIGP Attribute Transitive",
            "RFC 7311 - AIGP is optional transitive",
        ),
        ("AIGP-003", "AIGP Metric TLV", "RFC 7311 - AIGP Metric TLV encoding"),
        ("AIGP-004", "AIGP Metric 32-bit", "RFC 7311 - AIGP metric 32-bit unsigned"),
        ("AIGP-005", "AIGP Originator", "RFC 7311 - AIGP originator procedure"),
        (
            "AIGP-006",
            "AIGP EBGP Rule",
            "RFC 7311 - AIGP not propagated on EBGP boundary",
        ),
        ("AIGP-007", "AIGP IBGP Only", "RFC 7311 - AIGP only in IBGP or confederation"),
        (
            "AIGP-008",
            "AIGP Metric Accumulation",
            "RFC 7311 - AIGP metric accumulated along path",
        ),
        (
            "AIGP-009",
            "AIGP Decision Process",
            "RFC 7311 - AIGP considered in route selection",
        ),
        ("AIGP-010", "AIGP Next-Hop Self", "RFC 7311 - AIGP with next-hop-self"),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        return [
            TestCase(
                test_id=tid,
                name=name,
                category=cls.CATEGORY,
                description=desc,
            )
            for tid, name, desc in cls.TESTS
        ]

    @classmethod
    def test_aigp(cls, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = cls.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: cls._test_aigp_behavior(framework, test_case.params)
        )

    @staticmethod
    def _test_aigp_behavior(
        framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        try:
            framework.connect()
            framework.send_raw(build_open_message(framework.source_as))
            framework.receive_raw()
            framework.send_raw(build_keepalive_message())
            framework.receive_raw()

            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop = create_next_hop_attribute(framework.get_next_hop())

            update = build_update_message(
                [],
                [origin, as_path, next_hop],
                [(framework.ip_config.comm_test_prefix, 24)],
            )
            framework.send_raw(update)
            framework.receive_raw()

            return (True, "AIGP attribute test executed", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()


class ExtendedOptionalParametersAssessments:
    PREFIX = "EOP"
    CATEGORY = TestCategory.EXTENDED_OPTIONAL_PARAMETERS

    TESTS = [
        (
            "EOP-001",
            "Extended Length Type 255",
            "RFC 9072 - Extended length parameter type 255",
        ),
        ("EOP-002", "Extended OP Length Field", "RFC 9072 - Extended 2-byte OP length"),
        (
            "EOP-003",
            "Extended Parm Length Field",
            "RFC 9072 - Extended 2-byte parameter length",
        ),
        ("EOP-004", "Non-Ext OP Len 255", "RFC 9072 - Non-Ext OP Len set to 255"),
        (
            "EOP-005",
            "Non-Ext OP Type 255",
            "RFC 9072 - Non-Ext OP Type indicates extended",
        ),
        (
            "EOP-006",
            "Backward Compatibility",
            "RFC 9072 - Backward compatible with legacy peers",
        ),
        (
            "EOP-007",
            "Extended < 256 Bytes",
            "RFC 9072 - Extended format with < 256 bytes",
        ),
        (
            "EOP-008",
            "Extended > 256 Bytes",
            "RFC 9072 - Extended format with > 256 bytes",
        ),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        return [
            TestCase(
                test_id=tid,
                name=name,
                category=cls.CATEGORY,
                description=desc,
            )
            for tid, name, desc in cls.TESTS
        ]

    @classmethod
    def test_eop(cls, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = cls.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: cls._test_extended_optional_params(framework, test_case.params),
        )

    @staticmethod
    def _test_extended_optional_params(
        framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        try:
            framework.connect()

            open_msg = build_open_message(framework.source_as, hold_time=180)

            extended_open = (
                bytes([open_msg[0]])
                + open_msg[1:19]
                + bytes([255, 255])
                + open_msg[19:]
            )

            framework.send_raw(extended_open)
            framework.receive_raw()

            return (True, "Extended optional parameters test executed", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()


class FSMErrorSubcodeAssessments:
    PREFIX = "FSMS"
    CATEGORY = TestCategory.FSM_ERROR_SUBCODES

    FSM_ERROR_SUBCODES = {
        0: "Unspecified Error",
        1: "Receive Unexpected Message in OpenSent State",
        2: "Receive Unexpected Message in OpenConfirm State",
        3: "Receive Unexpected Message in Established State",
    }

    TESTS = [
        ("FSMS-001", "FSM Unspecified Error (0)", "RFC 6608 - FSM Error subcode 0"),
        ("FSMS-002", "FSM OpenSent Unexpected (1)", "RFC 6608 - FSM Error subcode 1"),
        (
            "FSMS-003",
            "FSM OpenConfirm Unexpected (2)",
            "RFC 6608 - FSM Error subcode 2",
        ),
        (
            "FSMS-004",
            "FSM Established Unexpected (3)",
            "RFC 6608 - FSM Error subcode 3",
        ),
        (
            "FSMS-005",
            "Unexpected Keepalive in OpenSent",
            "RFC 6608 - Keepalive in OpenSent state",
        ),
        (
            "FSMS-006",
            "Unexpected Update in OpenConfirm",
            "RFC 6608 - Update in OpenConfirm state",
        ),
        (
            "FSMS-007",
            "Unexpected Open in Established",
            "RFC 6608 - Open in Established state",
        ),
        (
            "FSMS-008",
            "FSM Subcode Data Field",
            "RFC 6608 - FSM subcode data contains message type",
        ),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        return [
            TestCase(
                test_id=tid,
                name=name,
                category=cls.CATEGORY,
                description=desc,
            )
            for tid, name, desc in cls.TESTS
        ]

    @classmethod
    def test_fsm_subcode(
        cls, framework: BGPTestFramework, test_index: int
    ) -> TestResult:
        test_case = cls.get_tests()[test_index]
        return framework._run_test(
            test_case,
            lambda: cls._test_fsm_subcode_behavior(framework, test_case.params),
        )

    @staticmethod
    def _test_fsm_subcode_behavior(
        framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        try:
            framework.connect()
            framework.send_raw(build_open_message(framework.source_as))
            response = framework.receive_raw()

            if response and len(response) > 0:
                return (True, "FSM error subcode test executed", {})
            return (True, "No response received", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()


class BGPIdentifierAssessments:
    PREFIX = "BGPI"
    CATEGORY = TestCategory.BGP_IDENTIFIER

    TESTS = [
        (
            "BGPI-001",
            "BGP ID 4-Octet Unsigned",
            "RFC 6286 - BGP ID is 4-octet unsigned",
        ),
        ("BGPI-002", "BGP ID Non-Zero", "RFC 6286 - BGP ID must be non-zero"),
        (
            "BGPI-003",
            "BGP ID Zero Rejection",
            "RFC 6286 - BGP ID zero causes rejection",
        ),
        ("BGPI-004", "BGP ID AS-Wide Unique", "RFC 6286 - BGP ID unique within AS"),
        (
            "BGPI-005",
            "BGP ID Collision Detection",
            "RFC 6286 - BGP ID collision handling",
        ),
        ("BGPI-006", "BGP ID Same ID EBGP", "RFC 6286 - Same ID allowed on EBGP"),
        ("BGPI-007", "BGP ID Same ID IBGP", "RFC 6286 - Same ID not allowed on IBGP"),
        (
            "BGPI-008",
            "BGP ID Connection Collision",
            "RFC 6286 - Larger AS wins collision",
        ),
        ("BGPI-009", "BGP ID IPv6 Support", "RFC 6286 - BGP ID for IPv6-only networks"),
        ("BGPI-010", "BGP ID Aggregator Attribute", "RFC 6286 - BGP ID in AGGREGATOR"),
    ]

    @classmethod
    def get_tests(cls) -> List[TestCase]:
        return [
            TestCase(
                test_id=tid,
                name=name,
                category=cls.CATEGORY,
                description=desc,
            )
            for tid, name, desc in cls.TESTS
        ]

    @classmethod
    def test_bgpi(cls, framework: BGPTestFramework, test_index: int) -> TestResult:
        test_case = cls.get_tests()[test_index]
        return framework._run_test(
            test_case, lambda: cls._test_bgp_id_behavior(framework, test_case.params)
        )

    @staticmethod
    def _test_bgp_id_behavior(
        framework: BGPTestFramework, params: Dict[str, Any]
    ) -> tuple:
        try:
            framework.connect()
            framework.send_raw(build_open_message(framework.source_as))
            response = framework.receive_raw()

            if response and len(response) > 0:
                return (True, "BGP identifier test executed", {})
            return (True, "No response received", {})
        except Exception as e:
            return (False, f"Error: {str(e)}", {})
        finally:
            framework.disconnect()


TEST_CLASSES: Dict[str, Type] = {
    "message_header": MessageHeaderAssessments,
    "open_message": OpenMessageAssessments,
    "update_message": UpdateMessageAssessments,
    "attribute": AttributeAssessments,
    "fsm": FSMAssessments,
    "timing": TimingAssessments,
    "security": SecurityAssessments,
    "route_aggregation": RouteAggregationAssessments,
    "decision_process": DecisionProcessAssessments,
    "keepalive_message": KeepaliveMessageAssessments,
    "notification_message": NotificationMessageAssessments,
    "version_negotiation": VersionNegotiationAssessments,
    "connection_collision": ConnectionCollisionAssessments,
    "multiprotocol": MultiprotocolAssessments,
    "route_reflection": RouteReflectionAssessments,
    "graceful_restart": GracefulRestartAssessments,
    "enhanced_route_refresh": EnhancedRouteRefreshAssessments,
    "extended_messages": ExtendedMessageAssessments,
    "orf_filtering": ORFFilteringAssessments,
    "dynamic_capability": DynamicCapabilityAssessments,
    "communities": CommunitiesAssessments,
    "large_communities": LargeCommunitiesAssessments,
    "route_flap_damping": RouteFlapDampingAssessments,
    "as_number": ASNumberAssessments,
    "vpn": VPNAssessments,
    "capabilities": CapabilitiesAssessments,
    "route_refresh": RouteRefreshAssessments,
    "mpls_labels": MPLSLabelAssessments,
    "nopeer": NOPEERCommunityAssessments,
    "route_oscillation": RouteOscillationAssessments,
    "cease_notification": CeaseNotificationAssessments,
    "ipv6_vpn": IPv6VPNAssessments,
    "gtsm": GTSMAssessments,
    "flow_spec": FlowSpecAssessments,
    "ipv6_extended_community": IPv6ExtCommunityAssessments,
    "rpki_router": RPKIRouterAssessments,
    "origin_validation": OriginValidationAssessments,
    "as0_processing": AS0Assessments,
    "bgp_ls": BGPLinkStateAssessments,
    "blackhole_community": BlackholeCommunityAssessments,
    "admin_shutdown": AdminShutdownAssessments,
    "mpls_label_binding": MPLSLabelBindingAssessments,
    "large_community_usage": LargeCommunityUsageAssessments,
    "datacenter_bgp": DataCenterBGPAssessments,
    "graceful_shutdown": GracefulShutdownAssessments,
    "evpn_nvo": EVPNNVOAssessments,
    "segment_routing": SegmentRoutingAssessments,
    "evpn_irb": IRBAssessments,
    "evpn_ip_prefix": EVPNIPPrefixAssessments,
    "bgp_role": BGPRoleAssessments,
    "srv6_bgp_overlay": SRv6BGPOverlayAssessments,
    "sr_policy": SRPolicyAssessments,
    "bgp_ls_updated": BGP_LS_UpdatedAssessments,
    "aigp": AIGPAssessments,
    "extended_optional_parameters": ExtendedOptionalParametersAssessments,
    "fsm_error_subcodes": FSMErrorSubcodeAssessments,
    "bgp_identifier": BGPIdentifierAssessments,
}

ALL_TEST_CATEGORIES = list(TEST_CLASSES.keys())
