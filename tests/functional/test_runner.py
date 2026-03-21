"""
Functional tests for BGP Test Runner
"""

from unittest.mock import Mock, patch

from bgp_test_framework.runner import TestRunner, TestConfiguration, BGPLogger
from bgp_test_framework.tests import TestCategory, TestResult


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
        assert "BGPv4 Adversarial Test Report" in report
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
