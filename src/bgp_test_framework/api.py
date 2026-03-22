"""
BGP Test Framework API
Provides programmatic access to BGP testing functionality
"""

from typing import List, Optional, Dict, Any, Callable, Tuple
from dataclasses import dataclass, field

from .constants import ORIGIN_TYPES
from .messages import (
    build_open_message,
    build_update_message,
    build_keepalive_message,
    build_notification_message,
    build_route_refresh_message,
    PathAttribute,
    BGPHeaderParser,
    BGPUpdateMessage,
    create_origin_attribute,
    create_as_path_attribute,
    create_next_hop_attribute,
    create_mp_reach_nlri_attribute,
    create_mp_unreach_nlri_attribute,
    create_originator_id_attribute,
    create_cluster_list_attribute,
)
from .tests import (
    BGPTestFramework,
    TestResult,
    TestCase,
    TEST_CLASSES,
)
from .runner import TestConfiguration, TestRunner, ComplianceMetrics


@dataclass
class BGPTestConfig:
    target_host: str = "127.0.0.1"
    target_port: int = 179
    source_as: int = 65001
    source_ip: str = "10.0.0.1"
    bgp_id: str = "10.0.0.1"
    hold_time: int = 180
    timeout: float = 5.0
    retry_count: int = 3


@dataclass
class TestOptions:
    categories: List[str] = field(default_factory=list)
    test_ids: List[str] = field(default_factory=list)
    verbose: bool = False
    debug: bool = False
    delay: float = 0.1


class BGPTestHarness:
    TEST_CLASSES = TEST_CLASSES

    def __init__(self, config: BGPTestConfig):
        self.config = config
        self.framework = BGPTestFramework(
            target_host=config.target_host,
            target_port=config.target_port,
            source_as=config.source_as,
            source_ip=config.source_ip,
            timeout=config.timeout,
        )

    def get_all_tests(self, category: Optional[str] = None) -> List[TestCase]:
        if category:
            if category in self.TEST_CLASSES:
                return self.TEST_CLASSES[category].get_tests()
            return []
        all_tests = []
        for test_class in self.TEST_CLASSES.values():
            all_tests.extend(test_class.get_tests())
        return all_tests

    def run_test(
        self, test_case: TestCase, test_method: Optional[Callable] = None
    ) -> TestResult:
        if test_method:
            return test_method(self.framework)
        return self.framework._run_test(
            test_case, lambda: (False, "Not implemented", {})
        )

    def run_category(
        self, category: str, options: TestOptions = TestOptions()
    ) -> List[TestResult]:
        if category not in self.TEST_CLASSES:
            return []
        test_class = self.TEST_CLASSES[category]
        tests = test_class.get_tests()

        if options.test_ids:
            tests = [t for t in tests if t.test_id in options.test_ids]

        results = []
        for test in tests:
            result = self.run_test(test)
            results.append(result)
        return results

    def run_all(self, options: TestOptions = TestOptions()) -> List[TestResult]:
        all_results = []
        categories = (
            options.categories if options.categories else list(self.TEST_CLASSES.keys())
        )

        for category in categories:
            if category in self.TEST_CLASSES:
                results = self.run_category(category, options)
                all_results.extend(results)
        return all_results

    def get_compliance_report(self, results: List[TestResult]) -> Dict[str, Any]:
        return ComplianceMetrics.generate_compliance_report(results)


class BGPMessageBuilder:
    @staticmethod
    def create_open(my_as: int, hold_time: int = 180, bgp_id: int = 0) -> bytes:
        return build_open_message(my_as, hold_time, bgp_id)

    @staticmethod
    def create_update(
        withdrawn_prefixes: Optional[List[Tuple[str, int]]] = None,
        path_attributes: Optional[List[PathAttribute]] = None,
        nlri_prefixes: Optional[List[Tuple[str, int]]] = None,
    ) -> bytes:
        return build_update_message(withdrawn_prefixes, path_attributes, nlri_prefixes)

    @staticmethod
    def create_keepalive() -> bytes:
        return build_keepalive_message()

    @staticmethod
    def create_notification(
        error_code: int, error_subcode: int, data: bytes = b""
    ) -> bytes:
        return build_notification_message(error_code, error_subcode, data)

    @staticmethod
    def create_route_refresh(afi: int, safi: int) -> bytes:
        return build_route_refresh_message(afi, safi)

    @staticmethod
    def create_origin_attribute(origin_type: str = "IGP") -> PathAttribute:
        return create_origin_attribute(ORIGIN_TYPES[origin_type])

    @staticmethod
    def create_as_path_attribute(
        as_numbers: List[int], segment_type: str = "AS_SEQUENCE"
    ) -> PathAttribute:
        return create_as_path_attribute(as_numbers)

    @staticmethod
    def create_next_hop_attribute(next_hop: str) -> PathAttribute:
        return create_next_hop_attribute(next_hop)

    @staticmethod
    def create_mp_reach(
        afi: int, safi: int, next_hop: bytes, nlri: bytes
    ) -> PathAttribute:
        return create_mp_reach_nlri_attribute(afi, safi, next_hop, nlri)

    @staticmethod
    def create_mp_unreach(afi: int, safi: int, withdrawn: bytes) -> PathAttribute:
        return create_mp_unreach_nlri_attribute(afi, safi, withdrawn)

    @staticmethod
    def create_originator_id(bgp_id: int) -> PathAttribute:
        return create_originator_id_attribute(bgp_id)

    @staticmethod
    def create_cluster_list(cluster_ids: List[int]) -> PathAttribute:
        return create_cluster_list_attribute(cluster_ids)


class BGPParser:
    @staticmethod
    def parse_header(data: bytes) -> Dict[str, Any]:
        marker, length, msg_type = BGPHeaderParser.parse(data)
        return {"marker": marker, "length": length, "type": msg_type}

    @staticmethod
    def parse_update(data: bytes) -> BGPUpdateMessage:
        return BGPUpdateMessage.parse(data)


def create_test_runner(
    config: BGPTestConfig, options: TestOptions = TestOptions()
) -> TestRunner:
    test_config = TestConfiguration(
        target_host=config.target_host,
        target_port=config.target_port,
        source_as=config.source_as,
        source_ip=config.source_ip,
        bgp_id=config.bgp_id,
        hold_time=config.hold_time,
        timeout=config.timeout,
        test_categories=options.categories,
        test_ids=options.test_ids,
        delay_between_tests=options.delay,
        retry_count=3,
        verbose=options.verbose,
        debug=options.debug,
        output_format="json",
        output_file=None,
    )
    return TestRunner(test_config)


def run_bgp_tests(
    target_host: str,
    source_as: int,
    categories: Optional[List[str]] = None,
    test_ids: Optional[List[str]] = None,
    verbose: bool = False,
    debug: bool = False,
) -> Dict[str, Any]:
    config = BGPTestConfig(target_host=target_host, source_as=source_as)
    options = TestOptions(
        categories=categories or [],
        test_ids=test_ids or [],
        verbose=verbose,
        debug=debug,
    )

    harness = BGPTestHarness(config)
    results = harness.run_all(options)
    report = harness.get_compliance_report(results)

    return {
        "results": results,
        "summary": report,
        "compliance_score": report.get("compliance_score", 0),
        "compliance_grade": report.get("compliance_grade", "N/A"),
    }
