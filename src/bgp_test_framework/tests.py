"""
BGPv4 Adversarial Test Cases
Based on RFC 4271 specifications
"""

import socket
import struct
import time
import random
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from .messages import (
    MARKER, build_open_message, build_update_message, build_notification_message,
    build_keepalive_message, BGPOpenMessage, BGPUpdateMessage, PathAttribute,
    create_origin_attribute, create_as_path_attribute, create_next_hop_attribute,
    create_multi_exit_disc_attribute, create_local_pref_attribute,
    create_aggregator_attribute, create_atomic_aggregate_attribute
)
from .constants import (
    MESSAGE_TYPES, PATH_ATTRIBUTE_TYPES, NOTIFICATION_ERROR_CODES,
    MESSAGE_HEADER_ERROR_SUBCODES, OPEN_MESSAGE_ERROR_SUBCODES,
    UPDATE_MESSAGE_ERROR_SUBCODES, ORIGIN_TYPES, AS_PATH_SEGMENT_TYPES,
    WELL_KNOWN_MANDATORY_ATTRIBUTES, MESSAGE_MIN_LENGTHS
)


class TestCategory(Enum):
    MESSAGE_HEADER = "message_header"
    OPEN_MESSAGE = "open_message"
    UPDATE_MESSAGE = "update_message"
    KEEPALIVE = "keepalive"
    NOTIFICATION = "notification"
    FSM = "fsm"
    TIMING = "timing"
    ATTRIBUTE = "attribute"
    SECURITY = "security"


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
    def __init__(self, target_host: str, target_port: int = 179,
                 source_as: int = 65001, source_ip: str = '0.0.0.1',
                 timeout: float = 5.0):
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
        except Exception as e:
            return False
    
    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
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
    
    def _create_header(self, msg_type: int, length: int, marker: bytes = MARKER) -> bytes:
        return marker + struct.pack('!HB', length, msg_type)
    
    def _run_test(self, test_case: TestCase, test_func: Callable) -> TestResult:
        result = TestResult(
            test_id=test_case.test_id,
            test_name=test_case.name,
            category=test_case.category,
            passed=False,
            expected_behavior=test_case.description,
            actual_behavior=""
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
            
            if test_case.expected_error_code and details.get('error_code'):
                result.error_code = details['error_code']
            if test_case.expected_error_subcode and details.get('error_subcode'):
                result.error_subcode = details['error_subcode']
                
        except Exception as e:
            result.actual_behavior = f"Exception: {str(e)}"
            result.details = {'exception': str(e)}
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
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['CONNECTION_NOT_SYNCHRONIZED']
            ),
            TestCase(
                test_id="MH-002",
                name="Invalid Marker - Partial",
                category=TestCategory.MESSAGE_HEADER,
                description="Send OPEN with partial invalid marker - RFC 4271 Section 6.1"
            ),
            TestCase(
                test_id="MH-003",
                name="Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length < 19 - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-004",
                name="Message Length Too Large",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length > 4096 - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-005",
                name="Message Length Zero",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with length = 0 - RFC 4271 Section 6.1"
            ),
            TestCase(
                test_id="MH-006",
                name="Invalid Message Type",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with invalid type (0) - RFC 4271 Section 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_TYPE']
            ),
            TestCase(
                test_id="MH-007",
                name="Invalid Message Type - Reserved",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with reserved type (5) - RFC 4271 Section 6.1"
            ),
            TestCase(
                test_id="MH-008",
                name="Message Type Future",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with future type (255) - RFC 4271 Section 6.1"
            ),
            TestCase(
                test_id="MH-009",
                name="OPEN Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send OPEN with length < 29 - RFC 4271 Section 4.2, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-010",
                name="UPDATE Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send UPDATE with length < 23 - RFC 4271 Section 4.3, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-011",
                name="KEEPALIVE Message Wrong Length",
                category=TestCategory.MESSAGE_HEADER,
                description="Send KEEPALIVE with length != 19 - RFC 4271 Section 4.4, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-012",
                name="NOTIFICATION Message Length Too Short",
                category=TestCategory.MESSAGE_HEADER,
                description="Send NOTIFICATION with length < 21 - RFC 4271 Section 4.5, 6.1",
                expected_error_code=NOTIFICATION_ERROR_CODES['MESSAGE_HEADER_ERROR'],
                expected_error_subcode=MESSAGE_HEADER_ERROR_SUBCODES['BAD_MESSAGE_LENGTH']
            ),
            TestCase(
                test_id="MH-013",
                name="Truncated Header",
                category=TestCategory.MESSAGE_HEADER,
                description="Send truncated BGP header - RFC 4271 Section 4.1"
            ),
            TestCase(
                test_id="MH-014",
                name="Extra Data After Message",
                category=TestCategory.MESSAGE_HEADER,
                description="Send message with extra padding - RFC 4271 Section 4.1"
            ),
        ]
    
    @staticmethod
    def test_invalid_marker(framework: BGPTestFramework) -> TestResult:
        test = TestCase(
            test_id="MH-001", name="Invalid Marker", category=TestCategory.MESSAGE_HEADER,
            description="Test with all zeros marker"
        )
        result = TestResult(test.test_id, test.name, test.category, False, test.description, "")
        
        if not framework.connect():
            result.actual_behavior = "Failed to connect"
            return result
        
        msg = build_open_message(framework.source_as)
        malicious_msg = bytearray(msg)
        malicious_msg[0:16] = b'\x00' * 16
        framework.send_raw(bytes(malicious_msg))
        
        response = framework.receive_raw()
        if response:
            if len(response) >= 21:
                error_code = response[19]
                error_subcode = response[20] if len(response) > 20 else 0
                result.passed = True
                result.actual_behavior = f"Received NOTIFICATION: code={error_code}, subcode={error_subcode}"
                result.details = {'error_code': error_code, 'error_subcode': error_subcode}
        else:
            result.actual_behavior = "No response received"
        
        framework.disconnect()
        return result
    
    @staticmethod
    def test_message_length_too_short(framework: BGPTestFramework) -> TestResult:
        result = TestResult("MH-003", "Message Length Too Short", 
                           TestCategory.MESSAGE_HEADER, False, 
                           "RFC 4271 Section 6.1", "")
        
        if not framework.connect():
            return result
        
        msg = framework._create_header(MESSAGE_TYPES['OPEN'], 10)
        msg += b'\x04\x19\x4e\x01\x00\xb4' + b'\x00' * 13
        framework.send_raw(msg)
        
        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received"
            result.details = {'error_code': response[19], 'error_subcode': response[20] if len(response) > 20 else 0}
        
        framework.disconnect()
        return result
    
    @staticmethod
    def test_message_length_too_large(framework: BGPTestFramework) -> TestResult:
        result = TestResult("MH-004", "Message Length Too Large",
                           TestCategory.MESSAGE_HEADER, False,
                           "RFC 4271 Section 6.1", "")
        
        if not framework.connect():
            return result
        
        msg = framework._create_header(MESSAGE_TYPES['KEEPALIVE'], 5000)
        framework.send_raw(msg)
        
        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for oversized message"
        
        framework.disconnect()
        return result
    
    @staticmethod
    def test_invalid_message_type(framework: BGPTestFramework) -> TestResult:
        result = TestResult("MH-006", "Invalid Message Type",
                           TestCategory.MESSAGE_HEADER, False,
                           "RFC 4271 Section 6.1", "")
        
        if not framework.connect():
            return result
        
        msg = framework._create_header(0, 19)
        framework.send_raw(msg)
        
        response = framework.receive_raw()
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received"
            result.details = {'error_code': response[19], 'error_subcode': response[20]}
        
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
                expected_error_code=NOTIFICATION_ERROR_CODES['OPEN_MESSAGE_ERROR'],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES['UNSUPPORTED_VERSION_NUMBER']
            ),
            TestCase(
                test_id="OP-002",
                name="BGP Version 0",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with version 0 - RFC 4271 Section 6.2"
            ),
            TestCase(
                test_id="OP-003",
                name="BGP Version 5",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with future version 5 - RFC 4271 Section 6.2"
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
                expected_error_code=NOTIFICATION_ERROR_CODES['OPEN_MESSAGE_ERROR'],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES['UNACCEPTABLE_HOLD_TIME']
            ),
            TestCase(
                test_id="OP-006",
                name="Hold Time Two",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time = 2 - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES['OPEN_MESSAGE_ERROR'],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES['UNACCEPTABLE_HOLD_TIME']
            ),
            TestCase(
                test_id="OP-007",
                name="Hold Time Too Large",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with hold time > 65535 - RFC 4271 Section 4.2"
            ),
            TestCase(
                test_id="OP-008",
                name="Invalid BGP Identifier - All Zeros",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with BGP ID = 0.0.0.0 - RFC 4271 Section 6.2"
            ),
            TestCase(
                test_id="OP-009",
                name="Invalid BGP Identifier - Multicast",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with multicast BGP ID - RFC 4271 Section 6.2"
            ),
            TestCase(
                test_id="OP-010",
                name="Invalid BGP Identifier - Reserved",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with 127.x.x.x BGP ID - RFC 4271 Section 6.2"
            ),
            TestCase(
                test_id="OP-011",
                name="Unknown Optional Parameter",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with unknown parameter type - RFC 4271 Section 6.2",
                expected_error_code=NOTIFICATION_ERROR_CODES['OPEN_MESSAGE_ERROR'],
                expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES['UNSUPPORTED_OPTIONAL_PARAMETER']
            ),
            TestCase(
                test_id="OP-012",
                name="Malformed Optional Parameter",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with malformed parameter - RFC 4271 Section 6.2"
            ),
            TestCase(
                test_id="OP-013",
                name="Parameter Length Mismatch",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with parameter length mismatch - RFC 4271 Section 4.2"
            ),
            TestCase(
                test_id="OP-014",
                name="AS Size Zero",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with AS = 0 - RFC 4271 Section 4.2"
            ),
            TestCase(
                test_id="OP-015",
                name="AS Reserved Value",
                category=TestCategory.OPEN_MESSAGE,
                description="Send OPEN with AS = 65535 - RFC 4271 Section 4.2"
            ),
        ]
    
    @staticmethod
    def test_unsupported_version(framework: BGPTestFramework, version: int = 0) -> TestResult:
        result = TestResult(f"OP-{version:03d}", f"Unsupported Version {version}",
                           TestCategory.OPEN_MESSAGE, False,
                           "RFC 4271 Section 6.2", "")
        
        if not framework.connect():
            return result
        
        import struct
        bgp_id = struct.unpack('!I', socket.inet_aton('192.168.1.1'))[0]
        data = struct.pack('!BHHI', version, framework.source_as, 180, bgp_id)
        data += struct.pack('!B', 0)
        msg = MARKER + struct.pack('!HB', 29, MESSAGE_TYPES['OPEN']) + data
        
        framework.send_raw(msg)
        response = framework.receive_raw()
        
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = f"NOTIFICATION received for version {version}"
            result.details = {'error_code': response[19], 'error_subcode': response[20]}
        
        framework.disconnect()
        return result
    
    @staticmethod
    def test_hold_time_one(framework: BGPTestFramework) -> TestResult:
        result = TestResult("OP-005", "Hold Time One",
                           TestCategory.OPEN_MESSAGE, False,
                           "RFC 4271 Section 6.2 - MUST reject hold time 1 or 2", "")
        
        if not framework.connect():
            return result
        
        import struct
        bgp_id = struct.unpack('!I', socket.inet_aton('192.168.1.1'))[0]
        data = struct.pack('!BHHI', 4, framework.source_as, 1, bgp_id)
        data += struct.pack('!B', 0)
        msg = MARKER + struct.pack('!HB', 29, MESSAGE_TYPES['OPEN']) + data
        
        framework.send_raw(msg)
        response = framework.receive_raw()
        
        if response and len(response) >= 21:
            result.passed = True
            result.actual_behavior = "NOTIFICATION received for hold time = 1"
            result.details = {'error_code': response[19], 'error_subcode': response[20]}
        
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
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['MISSING_WELL_KNOWN_ATTRIBUTE']
            ),
            TestCase(
                test_id="UP-002",
                name="Missing AS_PATH Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE without AS_PATH - RFC 4271 Section 5.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['MISSING_WELL_KNOWN_ATTRIBUTE']
            ),
            TestCase(
                test_id="UP-003",
                name="Missing NEXT_HOP Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE without NEXT_HOP - RFC 4271 Section 5.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['MISSING_WELL_KNOWN_ATTRIBUTE']
            ),
            TestCase(
                test_id="UP-004",
                name="Invalid ORIGIN Value",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with ORIGIN = 3 - RFC 4271 Section 5.1.1, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['INVALID_ORIGIN_ATTRIBUTE']
            ),
            TestCase(
                test_id="UP-005",
                name="Malformed AS_PATH",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with malformed AS_PATH - RFC 4271 Section 5.1.2, 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['MALFORMED_AS_PATH']
            ),
            TestCase(
                test_id="UP-006",
                name="AS_PATH Segment Length Mismatch",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with AS segment length > actual - RFC 4271 Section 5.1.2"
            ),
            TestCase(
                test_id="UP-007",
                name="AS_PATH Zero Length Segment",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with AS_SET length = 0 - RFC 4271 Section 5.1.2"
            ),
            TestCase(
                test_id="UP-008",
                name="Invalid NEXT_HOP - All Zeros",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with NEXT_HOP = 0.0.0.0 - RFC 4271 Section 5.1.3, 6.3"
            ),
            TestCase(
                test_id="UP-009",
                name="Invalid NEXT_HOP - Loopback",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with NEXT_HOP = 127.0.0.1 - RFC 4271 Section 5.1.3"
            ),
            TestCase(
                test_id="UP-010",
                name="Attribute Flags Conflict - ORIGIN",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with ORIGIN marked as optional - RFC 4271 Section 6.3"
            ),
            TestCase(
                test_id="UP-011",
                name="Attribute Length Mismatch",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with wrong attribute length - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['ATTRIBUTE_LENGTH_ERROR']
            ),
            TestCase(
                test_id="UP-012",
                name="Duplicate Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with duplicate attribute - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['MALFORMED_ATTRIBUTE_LIST']
            ),
            TestCase(
                test_id="UP-013",
                name="Invalid NLRI Prefix Length",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with prefix length > 32 - RFC 4271 Section 5.1"
            ),
            TestCase(
                test_id="UP-014",
                name="Invalid NLRI Prefix Bits",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with non-zero bits after prefix - RFC 4271 Section 4.3"
            ),
            TestCase(
                test_id="UP-015",
                name="Withdrawn Route Same as NLRI",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with prefix in both withdrawn and NLRI - RFC 4271 Section 4.3"
            ),
            TestCase(
                test_id="UP-016",
                name="Total Path Attribute Length Too Large",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with path attr length causing overflow - RFC 4271 Section 6.3"
            ),
            TestCase(
                test_id="UP-017",
                name="Withdrawn Routes Length Too Large",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with withdrawn routes length causing overflow - RFC 4271 Section 6.3"
            ),
            TestCase(
                test_id="UP-018",
                name="Unrecognized Well-known Attribute",
                category=TestCategory.UPDATE_MESSAGE,
                description="Send UPDATE with unrecognized well-known attribute - RFC 4271 Section 6.3",
                expected_error_code=NOTIFICATION_ERROR_CODES['UPDATE_MESSAGE_ERROR'],
                expected_error_subcode=UPDATE_MESSAGE_ERROR_SUBCODES['UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE']
            ),
        ]
    
    @staticmethod
    def test_missing_mandatory_attribute(framework: BGPTestFramework, 
                                       missing_attr: str) -> TestResult:
        test_ids = {'ORIGIN': 'UP-001', 'AS_PATH': 'UP-002', 'NEXT_HOP': 'UP-003'}
        result = TestResult(test_ids.get(missing_attr, 'UP-XXX'),
                           f"Missing {missing_attr}",
                           TestCategory.UPDATE_MESSAGE, False,
                           f"RFC 4271 Section 6.3 - Missing {missing_attr}", "")
        
        return result


class AttributeTests:
    
    @staticmethod
    def get_tests() -> List[TestCase]:
        return [
            TestCase(
                test_id="ATTR-001",
                name="AS_PATH Loop Detection",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with own AS in path - RFC 4271 Section 9.1.2"
            ),
            TestCase(
                test_id="ATTR-002",
                name="AS_PATH AS_CONFED_SEQUENCE",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_CONFED_SEQUENCE (type 3) - RFC 3065"
            ),
            TestCase(
                test_id="ATTR-003",
                name="AS_PATH AS_CONFED_SET",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS_CONFED_SET (type 4) - RFC 3065"
            ),
            TestCase(
                test_id="ATTR-004",
                name="AS_PATH Overflow",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AS path > 255 - RFC 4271 Section 5.1.2"
            ),
            TestCase(
                test_id="ATTR-005",
                name="LOCAL_PREF on EBGP",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with LOCAL_PREF to EBGP peer - RFC 4271 Section 5.1.5"
            ),
            TestCase(
                test_id="ATTR-006",
                name="MULTI_EXIT_DISC Reserved",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with MED > 0xFFFFFFFF - RFC 4271 Section 5.1.4"
            ),
            TestCase(
                test_id="ATTR-007",
                name="AGGREGATOR Invalid Length",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with AGGREGATOR length != 6 - RFC 4271 Section 5.1.7"
            ),
            TestCase(
                test_id="ATTR-008",
                name="ATOMIC_AGGREGATE Non-zero Length",
                category=TestCategory.ATTRIBUTE,
                description="Send UPDATE with ATOMIC_AGGREGATE length > 0 - RFC 4271 Section 5.1.6"
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
                description="Send UPDATE before OPEN - RFC 4271 Section 8.2"
            ),
            TestCase(
                test_id="FSM-002",
                name="UPDATE in Connect State",
                category=TestCategory.FSM,
                description="Send UPDATE in Connect state - RFC 4271 Section 8.2"
            ),
            TestCase(
                test_id="FSM-003",
                name="UPDATE in OpenSent State",
                category=TestCategory.FSM,
                description="Send UPDATE in OpenSent state - RFC 4271 Section 8.2"
            ),
            TestCase(
                test_id="FSM-004",
                name="UPDATE in OpenConfirm State",
                category=TestCategory.FSM,
                description="Send UPDATE in OpenConfirm state - RFC 4271 Section 8.2"
            ),
            TestCase(
                test_id="FSM-005",
                name="KEEPALIVE in Idle State",
                category=TestCategory.FSM,
                description="Send KEEPALIVE before OPEN - RFC 4271 Section 8.2"
            ),
            TestCase(
                test_id="FSM-006",
                name="OPEN in Established State",
                category=TestCategory.FSM,
                description="Send second OPEN in Established - RFC 4271 Section 6.8"
            ),
            TestCase(
                test_id="FSM-007",
                name="Unexpected NOTIFICATION in Established",
                category=TestCategory.FSM,
                description="Send NOTIFICATION to valid peer - RFC 4271 Section 6.4"
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
                description="Do not send KEEPALIVE until hold timer expires - RFC 4271 Section 8"
            ),
            TestCase(
                test_id="TIM-002",
                name="KEEPALIVE Rate Limit",
                category=TestCategory.TIMING,
                description="Send KEEPALIVE faster than 1 per second - RFC 4271 Section 4.4"
            ),
            TestCase(
                test_id="TIM-003",
                name="Zero Hold Time No KEEPALIVE",
                category=TestCategory.TIMING,
                description="Verify no KEEPALIVE when hold time = 0 - RFC 4271 Section 4.4"
            ),
            TestCase(
                test_id="TIM-004",
                name="KEEPALIVE Interval Too Large",
                category=TestCategory.TIMING,
                description="Do not send KEEPALIVE within hold time - RFC 4271 Section 8"
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
                description="Simultaneous connection from both sides - RFC 4271 Section 6.8"
            ),
            TestCase(
                test_id="SEC-002",
                name="BGP Identifier Collision",
                category=TestCategory.SECURITY,
                description="Connect with same BGP ID as peer - RFC 4271 Section 6.8"
            ),
            TestCase(
                test_id="SEC-003",
                name="Message Flooding",
                category=TestCategory.SECURITY,
                description="Flood with malformed messages - RFC 4271 Section 6"
            ),
            TestCase(
                test_id="SEC-004",
                name="AS_PATH Manipulation",
                category=TestCategory.SECURITY,
                description="Send UPDATE with private AS in path - RFC 4271 Section 5.1.2"
            ),
            TestCase(
                test_id="SEC-005",
                name="Route Dissemination to Wrong Peer",
                category=TestCategory.SECURITY,
                description="Send UPDATE to non-configured peer - RFC 4271 Section 8.2.1"
            ),
        ]
