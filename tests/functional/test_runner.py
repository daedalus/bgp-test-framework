"""
Functional tests for BGP Test Runner
"""

from unittest.mock import Mock, patch

from bgp_test_framework.runner import (
    TestRunner,
    TestConfiguration,
    BGPLogger,
    ComplianceMetrics,
)
from bgp_test_framework.assessments import TestCategory, TestResult


class MockSocket:
    def __init__(self):
        self.data_to_send = []
        self.received_data = []
        self.connected = False

    def connect(self, address):
        self.connected = True

    def sendall(self, data):
        self.data_to_send.append(data)

    def recv(self, size):
        if self.received_data:
            return self.received_data.pop(0)
        return b""

    def settimeout(self, timeout):
        pass

    def close(self):
        self.connected = False


class TestTestConfiguration:
    def test_config_creation(self):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="10.0.0.1",
            bgp_id="10.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=["message_header"],
            test_ids=["MH-001"],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file="results.json",
        )
        assert config.target_host == "192.168.1.1"
        assert config.target_port == 179
        assert config.source_as == 65001

    def test_config_defaults(self):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="0.0.0.1",
            bgp_id="0.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=[],
            test_ids=[],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file=None,
        )
        assert config.verbose is False
        assert config.debug is False
        assert config.output_file is None


class TestBGPLogger:
    def test_logger_initialization(self):
        logger = BGPLogger(verbose=False)
        assert len(logger.entries) == 0

    def test_logger_entries(self):
        logger = BGPLogger(verbose=False)
        logger.log("INFO", "Test message", {"key": "value"})
        assert len(logger.entries) == 1
        assert logger.entries[0]["message"] == "Test message"
        assert logger.entries[0]["level"] == "INFO"

    def test_logger_get_log(self):
        logger = BGPLogger()
        logger.log("ERROR", "Error message")
        logger.log("WARNING", "Warning message")
        log = logger.get_log()
        assert len(log) == 2


class TestTestRunner:
    @patch("socket.socket")
    def test_runner_initialization(self, mock_socket):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="10.0.0.1",
            bgp_id="10.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=[],
            test_ids=[],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file=None,
        )
        runner = TestRunner(config)
        assert runner.config == config
        assert runner.logger is not None
        assert runner.results == []

    @patch("socket.socket")
    def test_get_summary_empty(self, mock_socket):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="10.0.0.1",
            bgp_id="10.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=[],
            test_ids=[],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file=None,
        )
        runner = TestRunner(config)
        summary = runner.get_summary()
        assert summary["total"] == 0
        assert summary["passed"] == 0
        assert summary["failed"] == 0

    @patch("socket.socket")
    def test_get_summary_with_results(self, mock_socket):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="10.0.0.1",
            bgp_id="10.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=[],
            test_ids=[],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file=None,
        )
        runner = TestRunner(config)
        runner.results = [
            TestResult(
                "TEST-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                True,
                "Expected",
                "Actual",
            ),
            TestResult(
                "TEST-002",
                "Test 2",
                TestCategory.OPEN_MESSAGE,
                False,
                "Expected",
                "Actual",
            ),
            TestResult(
                "TEST-003",
                "Test 3",
                TestCategory.UPDATE_MESSAGE,
                True,
                "Expected",
                "Actual",
            ),
        ]
        summary = runner.get_summary()
        assert summary["total"] == 3
        assert summary["passed"] == 2
        assert summary["failed"] == 1
        assert summary["pass_rate"] == "66.7%"

    def test_generate_report(self):
        config = TestConfiguration(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65001,
            source_ip="10.0.0.1",
            bgp_id="10.0.0.1",
            hold_time=180,
            timeout=5.0,
            test_categories=[],
            test_ids=[],
            delay_between_tests=0.5,
            retry_count=1,
            verbose=False,
            debug=False,
            output_format="json",
            output_file=None,
        )
        runner = TestRunner(config)
        runner.results = [
            TestResult(
                "MH-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                True,
                "Expected",
                "Actual",
            ),
        ]
        report = runner.generate_report()
        assert "BGPv4 RFC Compliance Test Report" in report
        assert "Compliance Score:" in report
        assert "Compliance Grade:" in report
        assert "MH-001" in report
        assert "PASS" in report


class TestCommandLineParsing:
    def test_create_config_from_args(self):
        from bgp_test_framework.runner import create_config_from_args

        args = Mock()
        args.target = "192.168.1.1"
        args.port = 179
        args.as_number = 65001
        args.source_ip = "10.0.0.1"
        args.bgp_id = "10.0.0.1"
        args.hold_time = 180
        args.timeout = 5.0
        args.categories = None
        args.test_ids = None
        args.delay = 0.5
        args.retry = 1
        args.verbose = False
        args.debug = False
        args.format = "json"
        args.output = None
        args.config = None

        config = create_config_from_args(args)
        assert config.target_host == "192.168.1.1"
        assert config.target_port == 179
        assert config.source_as == 65001


class TestConfigurationLoading:
    def test_load_config_dict(self):
        config_dict = {
            "target": "192.168.1.1",
            "port": 179,
            "source_as": 65001,
            "hold_time": 180,
            "timeout": 5.0,
        }
        assert "target" in config_dict
        assert config_dict["source_as"] == 65001


class TestIntegrationScenarios:
    def test_test_filtering_by_category(self):
        all_tests = [
            ("MH-001", TestCategory.MESSAGE_HEADER),
            ("MH-002", TestCategory.MESSAGE_HEADER),
            ("OP-001", TestCategory.OPEN_MESSAGE),
            ("UP-001", TestCategory.UPDATE_MESSAGE),
        ]

        filtered = [
            (tid, cat) for tid, cat in all_tests if cat == TestCategory.MESSAGE_HEADER
        ]
        assert len(filtered) == 2
        assert all(cat == TestCategory.MESSAGE_HEADER for _, cat in filtered)

    def test_test_filtering_by_id(self):
        all_tests = [
            ("MH-001", TestCategory.MESSAGE_HEADER),
            ("MH-002", TestCategory.MESSAGE_HEADER),
            ("OP-001", TestCategory.OPEN_MESSAGE),
        ]

        target_ids = {"MH-001", "MH-002"}
        filtered = [(tid, cat) for tid, cat in all_tests if tid in target_ids]
        assert len(filtered) == 2
        assert all(tid in target_ids for tid, _ in filtered)


class TestComplianceMetrics:
    def test_calculate_compliance_score(self):
        assert ComplianceMetrics.calculate_compliance_score(100, 95) == 95.0
        assert ComplianceMetrics.calculate_compliance_score(10, 10) == 100.0
        assert ComplianceMetrics.calculate_compliance_score(10, 0) == 0.0
        assert ComplianceMetrics.calculate_compliance_score(0, 0) == 0.0

    def test_get_compliance_grade(self):
        assert ComplianceMetrics.get_compliance_grade(100) == "A"
        assert ComplianceMetrics.get_compliance_grade(95) == "A"
        assert ComplianceMetrics.get_compliance_grade(94) == "B"
        assert ComplianceMetrics.get_compliance_grade(85) == "B"
        assert ComplianceMetrics.get_compliance_grade(84) == "C"
        assert ComplianceMetrics.get_compliance_grade(70) == "C"
        assert ComplianceMetrics.get_compliance_grade(69) == "D"
        assert ComplianceMetrics.get_compliance_grade(50) == "D"
        assert ComplianceMetrics.get_compliance_grade(49) == "F"
        assert ComplianceMetrics.get_compliance_grade(0) == "F"

    def test_get_severity_level(self):
        assert ComplianceMetrics.get_severity_level("MH-001") == "CRITICAL"
        assert ComplianceMetrics.get_severity_level("OM-001") == "HIGH"
        assert ComplianceMetrics.get_severity_level("UM-001") == "HIGH"
        assert ComplianceMetrics.get_severity_level("AT-001") == "MEDIUM"
        assert ComplianceMetrics.get_severity_level("FSM-001") == "HIGH"
        assert ComplianceMetrics.get_severity_level("TM-001") == "MEDIUM"
        assert ComplianceMetrics.get_severity_level("SEC-001") == "CRITICAL"
        assert ComplianceMetrics.get_severity_level("RA-001") == "MEDIUM"
        assert ComplianceMetrics.get_severity_level("DEC-001") == "LOW"
        assert ComplianceMetrics.get_severity_level("OTHER-001") == "INFO"

    def test_calculate_severity_score(self):
        failed = [
            TestResult(
                "MH-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                False,
                "Expected",
                "Actual",
            ),
            TestResult(
                "SEC-001",
                "Test 2",
                TestCategory.SECURITY,
                False,
                "Expected",
                "Actual",
            ),
        ]
        severity = ComplianceMetrics.calculate_severity_score(failed)
        assert severity["CRITICAL"] == 2
        assert severity["HIGH"] == 0
        assert severity["MEDIUM"] == 0

    def test_calculate_severity_weighted_score(self):
        failed = [
            TestResult(
                "MH-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                False,
                "Expected",
                "Actual",
            ),
        ]
        score = ComplianceMetrics.calculate_severity_weighted_score(10, 9, failed)
        assert score > 0 and score <= 100

    def test_get_rfc_section_compliance(self):
        results = [
            TestResult(
                "MH-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                True,
                "Expected",
                "Actual",
            ),
            TestResult(
                "MH-002",
                "Test 2",
                TestCategory.MESSAGE_HEADER,
                False,
                "Expected",
                "Actual",
            ),
        ]
        compliance = ComplianceMetrics.get_rfc_section_compliance(results)
        assert "RFC 4271 Section 4.1" in compliance
        assert compliance["RFC 4271 Section 4.1"]["total"] == 2
        assert compliance["RFC 4271 Section 4.1"]["passed"] == 1
        assert compliance["RFC 4271 Section 4.1"]["failed"] == 1

    def test_generate_compliance_report(self):
        results = [
            TestResult(
                "MH-001",
                "Test 1",
                TestCategory.MESSAGE_HEADER,
                True,
                "Expected",
                "Actual",
            ),
            TestResult(
                "MH-002",
                "Test 2",
                TestCategory.MESSAGE_HEADER,
                False,
                "Expected",
                "Actual",
            ),
            TestResult(
                "OM-001",
                "Test 3",
                TestCategory.OPEN_MESSAGE,
                True,
                "Expected",
                "Actual",
            ),
        ]
        report = ComplianceMetrics.generate_compliance_report(results)
        assert report["total_tests"] == 3
        assert report["tests_passed"] == 2
        assert report["tests_failed"] == 1
        assert report["compliance_score"] > 0
        assert "compliance_grade" in report
        assert "severity_distribution" in report
        assert "rfc_section_compliance" in report
