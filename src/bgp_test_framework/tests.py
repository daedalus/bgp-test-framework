"""
BGPv4 Adversarial Test Cases
Based on RFC 4271 specifications
"""

import socket
import struct
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from .messages import (
    MARKER,
    build_open_message,
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
    BGP_LS = "bgp_ls"
    CONFEDERATION = "confederation"
    GRACEFUL_RESTART = "graceful_restart"
    ENHANCED_ROUTE_REFRESH = "enhanced_route_refresh"
    EXTENDED_MESSAGES = "extended_messages"
    ORF_FILTERING = "orf_filtering"
    DYNAMIC_CAPABILITY = "dynamic_capability"


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


class BGPTestFramework:
    def __init__(
        self,
        target_host: str,
        target_port: int = 179,
        source_as: int = 65001,
        source_ip: str = "0.0.0.1",
        timeout: float = 5.0,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.source_as = source_as
        self.source_ip = source_ip
        self.timeout = timeout
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

    def send_raw(self, data: bytes) -> bool:
        if not self.sock:
            return False
        try:
            self.sock.sendall(data)
            return True
        except Exception:
            return False

    def receive_raw(self, size: int = 4096) -> Optional[bytes]:
        if not self.sock:
            return None
        try:
            return self.sock.recv(size)
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


class MessageHeaderTests:

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


class OpenMessageTests:

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


class UpdateMessageTests:

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


class AttributeTests:

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


class FSMTests:

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


class TimingTests:

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


class SecurityTests:

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


class RouteAggregationTests:

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


class DecisionProcessTests:

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


class KeepaliveMessageTests:
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


class NotificationMessageTests:
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


class VersionNegotiationTests:
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


class ConnectionCollisionTests:
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


class MultiprotocolTests:
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


class RouteReflectionTests:
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


class BGPSecurityTests:
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


class GracefulRestartTests:
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


class EnhancedRouteRefreshTests:
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


class ExtendedMessageTests:
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


class ORFFilteringTests:
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


class DynamicCapabilityTests:
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
