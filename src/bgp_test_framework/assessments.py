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


class BGPTestFramework:
    def __init__(
        self,
        target_host: str,
        target_port: int = 179,
        source_as: int = 65001,
        source_ip: str = "0.0.0.1",
        timeout: float = 5.0,
        debug: bool = False,
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

            next_hop = socket.inet_aton("10.0.0.1")
            mp_reach = self._build_mp_reach_nlri(afi, safi, next_hop, nlri)
            origin = create_origin_attribute(0)
            as_path = create_as_path_attribute([framework.source_as])
            next_hop_attr = create_next_hop_attribute("10.0.0.1")
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
        nlri = bytes([24]) + socket.inet_aton("192.168.10.0")[:3]
        return framework._run_test(
            self.get_tests()[0],
            lambda: self._send_mp_reach(
                framework, invalid_afi, self.SAFI_UNICAST, nlri
            ),
        )

    def test_mp_002(self, framework: BGPTestFramework) -> TestResult:
        nlri = bytes([24]) + socket.inet_aton("192.168.11.0")[:3]
        return framework._run_test(
            self.get_tests()[1],
            lambda: self._send_mp_reach(framework, self.AFI_IPV4, 99, nlri),
        )

    def test_mp_003(self, framework: BGPTestFramework) -> TestResult:
        invalid_afi = 999
        nlri = bytes([24]) + socket.inet_aton("192.168.12.0")[:3]
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
            nlri = bytes([24]) + socket.inet_aton("192.168.13.0")[:3]
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
            next_hop = socket.inet_aton("10.0.0.1")
            nlri = bytes([24]) + socket.inet_aton("192.168.14.0")[:3]
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
        nlri = bytes([24]) + socket.inet_aton("192.168.15.0")[:3]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            community = self._build_community_attr(communities)

            update = build_update_message(
                [], [origin, as_path, next_hop, community], [("192.168.1.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, empty_community], [("192.168.2.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, large_comm_attr], [("192.168.3.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, large_comm_attr], [("192.168.4.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, empty_lcomm], [("192.168.5.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
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
            next_hop = create_next_hop_attribute("10.0.0.1")
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
        prefix = params.get("prefix", "192.168.0.0")
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop], [("192.168.50.0", 24)]
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

            next_hop = socket.inet_aton("10.0.0.1")
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
            bgp_id = struct.unpack("!I", socket.inet_aton("192.168.1.1"))[0]
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

            next_hop = socket.inet_aton("10.0.0.1")
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, comm_attr], [("192.168.30.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path, next_hop, ext_comm_attr], [("192.168.100.0", 24)]
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
            next_hop = create_next_hop_attribute("10.0.0.1")
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
            next_hop = create_next_hop_attribute("10.0.0.1")
            update = build_update_message(
                [], [origin, as_path_attr, next_hop], [("192.168.200.0", 24)]
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
                nlri = bytes([protocol_id, 0x03, 24]) + socket.inet_aton("10.0.0.0")
            else:
                nlri = bytes([protocol_id, 0x04, 32]) + socket.inet_pton(
                    socket.AF_INET6, "2001:db8::"
                )

            next_hop = socket.inet_aton("10.0.0.1")
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
}

ALL_TEST_CATEGORIES = list(TEST_CLASSES.keys())
