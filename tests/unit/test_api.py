"""
Unit tests for BGP Test Framework API
"""

import pytest
from bgp_test_framework.api import (
    BGPTestConfig,
    TestOptions,
    BGPTestHarness,
    BGPMessageBuilder,
    BGPParser,
    create_test_runner,
    run_bgp_tests,
)


class TestBGPTestConfig:
    def test_default_config(self):
        config = BGPTestConfig()
        assert config.target_host == "127.0.0.1"
        assert config.target_port == 179
        assert config.source_as == 65001

    def test_custom_config(self):
        config = BGPTestConfig(
            target_host="192.168.1.1",
            target_port=179,
            source_as=65000,
        )
        assert config.target_host == "192.168.1.1"
        assert config.source_as == 65000


class TestTestOptions:
    def test_default_options(self):
        options = TestOptions()
        assert options.categories == []
        assert options.test_ids == []
        assert options.verbose is False
        assert options.debug is False

    def test_custom_options(self):
        options = TestOptions(
            categories=["message_header"],
            test_ids=["MH-001"],
            verbose=True,
        )
        assert options.categories == ["message_header"]
        assert options.test_ids == ["MH-001"]
        assert options.verbose is True


class TestBGPTestHarness:
    def test_harness_creation(self):
        config = BGPTestConfig(target_host="192.168.1.1", source_as=65001)
        harness = BGPTestHarness(config)
        assert harness.config.target_host == "192.168.1.1"
        assert harness.framework is not None

    def test_get_all_tests(self):
        config = BGPTestConfig()
        harness = BGPTestHarness(config)
        tests = harness.get_all_tests()
        assert len(tests) > 0

    def test_get_tests_by_category(self):
        config = BGPTestConfig()
        harness = BGPTestHarness(config)
        tests = harness.get_all_tests("message_header")
        assert all(t.category.value == "message_header" for t in tests)

    def test_invalid_category_returns_empty(self):
        config = BGPTestConfig()
        harness = BGPTestHarness(config)
        tests = harness.get_all_tests("invalid_category")
        assert tests == []


class TestBGPMessageBuilder:
    def test_create_open(self):
        msg = BGPMessageBuilder.create_open(my_as=65001)
        assert len(msg) >= 19
        assert msg[0:16] == b"\xff" * 16

    def test_create_keepalive(self):
        msg = BGPMessageBuilder.create_keepalive()
        assert len(msg) == 19

    def test_create_notification(self):
        msg = BGPMessageBuilder.create_notification(1, 1)
        assert len(msg) >= 21

    def test_create_route_refresh(self):
        msg = BGPMessageBuilder.create_route_refresh(afi=1, safi=1)
        assert len(msg) == 23

    def test_create_origin_attribute(self):
        attr = BGPMessageBuilder.create_origin_attribute("IGP")
        assert attr.attr_type == 1

    def test_create_as_path_attribute(self):
        attr = BGPMessageBuilder.create_as_path_attribute([65001, 65002])
        assert attr.attr_type == 2

    def test_create_next_hop_attribute(self):
        attr = BGPMessageBuilder.create_next_hop_attribute("192.168.1.1")
        assert attr.attr_type == 3

    def test_create_mp_reach(self):
        attr = BGPMessageBuilder.create_mp_reach(2, 1, b"\x00\x00\x00\x00", b"")
        assert attr.attr_type == 14

    def test_create_mp_unreach(self):
        attr = BGPMessageBuilder.create_mp_unreach(2, 1, b"")
        assert attr.attr_type == 15

    def test_create_originator_id(self):
        attr = BGPMessageBuilder.create_originator_id(0x0A000001)
        assert attr.attr_type == 9

    def test_create_cluster_list(self):
        attr = BGPMessageBuilder.create_cluster_list([1, 2, 3])
        assert attr.attr_type == 10


class TestBGPParser:
    def test_parse_header(self):
        from bgp_test_framework.messages import build_open_message

        msg = build_open_message(65001)
        parsed = BGPParser.parse_header(msg)
        assert "length" in parsed
        assert "type" in parsed


class TestCreateTestRunner:
    def test_create_runner(self):
        config = BGPTestConfig(target_host="192.168.1.1", source_as=65001)
        runner = create_test_runner(config)
        assert runner.config.target_host == "192.168.1.1"
        assert runner.config.source_as == 65001


class TestRunBgpTests:
    def test_run_bgp_tests_structure(self):
        result = run_bgp_tests("192.168.1.1", 65001, debug=True)
        assert "results" in result
        assert "summary" in result
        assert "compliance_score" in result
        assert "compliance_grade" in result
