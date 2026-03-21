"""
Unit tests for BGP test cases
"""

from bgp_test_framework.tests import (
    TestCategory,
    TestResult,
    BGPTestFramework,
    TestCase,
    MessageHeaderTests,
    OpenMessageTests,
    UpdateMessageTests,
    AttributeTests,
    FSMTests,
    TimingTests,
    SecurityTests,
)
from bgp_test_framework.constants import (
    NOTIFICATION_ERROR_CODES,
    MESSAGE_HEADER_ERROR_SUBCODES,
    OPEN_MESSAGE_ERROR_SUBCODES,
    UPDATE_MESSAGE_ERROR_SUBCODES,
)


class TestTestCase:
    def test_test_case_creation(self):
        test = TestCase(
            test_id="TEST-001",
            name="Test Case 1",
            category=TestCategory.MESSAGE_HEADER,
            description="Test description",
        )
        assert test.test_id == "TEST-001"
        assert test.category == TestCategory.MESSAGE_HEADER

    def test_test_case_with_error_codes(self):
        test = TestCase(
            test_id="TEST-002",
            name="Test Case 2",
            category=TestCategory.OPEN_MESSAGE,
            description="Test with error codes",
            expected_error_code=NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"],
            expected_error_subcode=OPEN_MESSAGE_ERROR_SUBCODES[
                "UNSUPPORTED_VERSION_NUMBER"
            ],
        )
        assert test.expected_error_code == 2
        assert test.expected_error_subcode == 1


class TestTestResult:
    def test_test_result_creation(self):
        result = TestResult(
            test_id="TEST-001",
            test_name="Test Result",
            category=TestCategory.MESSAGE_HEADER,
            passed=True,
            expected_behavior="Should return error",
            actual_behavior="Returned error",
        )
        assert result.passed is True
        assert result.test_id == "TEST-001"

    def test_test_result_with_details(self):
        result = TestResult(
            test_id="TEST-002",
            test_name="Test Result with Details",
            category=TestCategory.OPEN_MESSAGE,
            passed=True,
            expected_behavior="Expected",
            actual_behavior="Actual",
            details={"error_code": 1, "error_subcode": 2},
        )
        assert result.details["error_code"] == 1


class TestBGPTestFramework:
    def test_framework_initialization(self):
        framework = BGPTestFramework(
            target_host="127.0.0.1", target_port=179, source_as=65001
        )
        assert framework.target_host == "127.0.0.1"
        assert framework.target_port == 179
        assert framework.source_as == 65001
        assert framework.timeout == 5.0

    def test_framework_custom_timeout(self):
        framework = BGPTestFramework(
            target_host="127.0.0.1", target_port=179, source_as=65001, timeout=10.0
        )
        assert framework.timeout == 10.0


class TestMessageHeaderTests:
    def test_get_tests(self):
        tests = MessageHeaderTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.MESSAGE_HEADER for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in MessageHeaderTests.get_tests()}
        assert "MH-001" in tests
        assert "MH-003" in tests
        assert "MH-004" in tests
        assert "MH-006" in tests


class TestOpenMessageTests:
    def test_get_tests(self):
        tests = OpenMessageTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.OPEN_MESSAGE for t in tests)

    def test_version_tests_exist(self):
        tests = {t.test_id: t for t in OpenMessageTests.get_tests()}
        assert "OP-001" in tests
        assert "OP-002" in tests
        assert "OP-003" in tests

    def test_hold_time_tests_exist(self):
        tests = {t.test_id: t for t in OpenMessageTests.get_tests()}
        assert "OP-004" in tests
        assert "OP-005" in tests
        assert "OP-006" in tests


class TestUpdateMessageTests:
    def test_get_tests(self):
        tests = UpdateMessageTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.UPDATE_MESSAGE for t in tests)

    def test_mandatory_attribute_tests(self):
        tests = {t.test_id: t for t in UpdateMessageTests.get_tests()}
        assert "UP-001" in tests
        assert "UP-002" in tests
        assert "UP-003" in tests

    def test_origin_tests(self):
        tests = {t.test_id: t for t in UpdateMessageTests.get_tests()}
        assert "UP-004" in tests


class TestAttributeTests:
    def test_get_tests(self):
        tests = AttributeTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.ATTRIBUTE for t in tests)

    def test_as_path_tests(self):
        tests = {t.test_id: t for t in AttributeTests.get_tests()}
        assert "ATTR-001" in tests
        assert "ATTR-004" in tests


class TestFSMTests:
    def test_get_tests(self):
        tests = FSMTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.FSM for t in tests)

    def test_update_in_wrong_state_tests(self):
        tests = {t.test_id: t for t in FSMTests.get_tests()}
        assert "FSM-001" in tests
        assert "FSM-002" in tests


class TestTimingTests:
    def test_get_tests(self):
        tests = TimingTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.TIMING for t in tests)

    def test_keepalive_tests(self):
        tests = {t.test_id: t for t in TimingTests.get_tests()}
        assert "TIM-001" in tests
        assert "TIM-002" in tests


class TestSecurityTests:
    def test_get_tests(self):
        tests = SecurityTests.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.SECURITY for t in tests)

    def test_collision_tests(self):
        tests = {t.test_id: t for t in SecurityTests.get_tests()}
        assert "SEC-001" in tests
        assert "SEC-002" in tests


class TestTestCategories:
    def test_all_categories_defined(self):
        assert len(TestCategory) == 11
        assert TestCategory.MESSAGE_HEADER.value == "message_header"
        assert TestCategory.OPEN_MESSAGE.value == "open_message"
        assert TestCategory.UPDATE_MESSAGE.value == "update_message"
        assert TestCategory.ATTRIBUTE.value == "attribute"
        assert TestCategory.FSM.value == "fsm"
        assert TestCategory.TIMING.value == "timing"
        assert TestCategory.NOTIFICATION.value == "notification"
        assert TestCategory.SECURITY.value == "security"
        assert TestCategory.ROUTE_AGGREGATION.value == "route_aggregation"
        assert TestCategory.DECISION_PROCESS.value == "decision_process"


class TestNotificationErrorCodes:
    def test_all_error_codes_defined(self):
        assert NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"] == 1
        assert NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"] == 2
        assert NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"] == 3
        assert NOTIFICATION_ERROR_CODES["HOLD_TIMER_EXPIRED"] == 4
        assert NOTIFICATION_ERROR_CODES["FINITE_STATE_MACHINE_ERROR"] == 5
        assert NOTIFICATION_ERROR_CODES["CEASE"] == 6


class TestMessageHeaderErrorSubcodes:
    def test_all_subcodes_defined(self):
        assert MESSAGE_HEADER_ERROR_SUBCODES["CONNECTION_NOT_SYNCHRONIZED"] == 1
        assert MESSAGE_HEADER_ERROR_SUBCODES["BAD_MESSAGE_LENGTH"] == 2
        assert MESSAGE_HEADER_ERROR_SUBCODES["BAD_MESSAGE_TYPE"] == 3


class TestOpenMessageErrorSubcodes:
    def test_all_subcodes_defined(self):
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNSUPPORTED_VERSION_NUMBER"] == 1
        assert OPEN_MESSAGE_ERROR_SUBCODES["BAD_PEER_AS"] == 2
        assert OPEN_MESSAGE_ERROR_SUBCODES["BAD_BGP_IDENTIFIER"] == 3
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNSUPPORTED_OPTIONAL_PARAMETER"] == 4
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNACCEPTABLE_HOLD_TIME"] == 6


class TestUpdateMessageErrorSubcodes:
    def test_all_subcodes_defined(self):
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MALFORMED_ATTRIBUTE_LIST"] == 1
        assert UPDATE_MESSAGE_ERROR_SUBCODES["UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE"] == 2
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MISSING_WELL_KNOWN_ATTRIBUTE"] == 3
        assert UPDATE_MESSAGE_ERROR_SUBCODES["ATTRIBUTE_FLAGS_ERROR"] == 4
        assert UPDATE_MESSAGE_ERROR_SUBCODES["ATTRIBUTE_LENGTH_ERROR"] == 5
        assert UPDATE_MESSAGE_ERROR_SUBCODES["INVALID_ORIGIN_ATTRIBUTE"] == 6
        assert UPDATE_MESSAGE_ERROR_SUBCODES["INVALID_NEXT_HOP_ATTRIBUTE"] == 8
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MALFORMED_AS_PATH"] == 11
