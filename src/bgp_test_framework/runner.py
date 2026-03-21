"""
BGPv4 Test Runner
Executes adversarial tests against target BGP implementations
"""

import socket
import struct
import time
import random
import argparse
import yaml
import logging
import sys
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import (
    MARKER, MESSAGE_TYPES, PATH_ATTRIBUTE_TYPES, NOTIFICATION_ERROR_CODES,
    MESSAGE_HEADER_ERROR_SUBCODES, OPEN_MESSAGE_ERROR_SUBCODES,
    UPDATE_MESSAGE_ERROR_SUBCODES, ORIGIN_TYPES, AS_PATH_SEGMENT_TYPES,
    BGP_FSM_STATES
)
from .messages import (
    build_open_message, build_update_message, build_notification_message,
    build_keepalive_message, PathAttribute, BGPKeepaliveMessage,
    create_origin_attribute, create_as_path_attribute, create_next_hop_attribute
)
from .tests import (
    BGPTestFramework, TestResult, TestCategory, TestCase, MessageHeaderTests,
    OpenMessageTests, UpdateMessageTests, AttributeTests, FSMTests,
    TimingTests, SecurityTests
)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class TestConfiguration:
    target_host: str
    target_port: int
    source_as: int
    source_ip: str
    bgp_id: str
    hold_time: int
    timeout: float
    test_categories: List[str]
    test_ids: List[str]
    delay_between_tests: float
    retry_count: int
    verbose: bool
    output_format: str
    output_file: Optional[str]


class BGPLogger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.entries: List[Dict[str, Any]] = []
    
    def log(self, level: str, message: str, details: Optional[Dict] = None):
        entry = {
            'timestamp': time.time(),
            'level': level,
            'message': message
        }
        if details:
            entry['details'] = details
        self.entries.append(entry)
        
        if self.verbose or level in ['ERROR', 'CRITICAL']:
            log_func = getattr(logger, level.lower(), logger.info)
            log_func(message)
    
    def get_log(self) -> List[Dict[str, Any]]:
        return self.entries


class TestRunner:
    def __init__(self, config: TestConfiguration):
        self.config = config
        self.framework: Optional[BGPTestFramework] = None
        self.logger = BGPLogger(config.verbose)
        self.results: List[TestResult] = []
    
    def _create_framework(self) -> BGPTestFramework:
        return BGPTestFramework(
            target_host=self.config.target_host,
            target_port=self.config.target_port,
            source_as=self.config.source_as,
            source_ip=self.config.source_ip,
            timeout=self.config.timeout
        )
    
    def _get_all_tests(self) -> List[Tuple[TestCase, callable]]:
        tests = []
        test_classes = [
            MessageHeaderTests,
            OpenMessageTests,
            UpdateMessageTests,
            AttributeTests,
            FSMTests,
            TimingTests,
            SecurityTests
        ]
        
        for test_class in test_classes:
            for test in test_class.get_tests():
                method_name = f"test_{test.test_id.lower().replace('-', '_')}"
                if hasattr(test_class, method_name):
                    tests.append((test, getattr(test_class, method_name)))
                else:
                    tests.append((test, self._generic_test))
        
        return tests
    
    def _filter_tests(self, tests: List[Tuple[TestCase, callable]]) -> List[Tuple[TestCase, callable]]:
        if self.config.test_ids:
            tests = [(t, f) for t, f in tests if t.test_id in self.config.test_ids]
        
        if self.config.test_categories:
            tests = [(t, f) for t, f in tests 
                    if t.category.value in self.config.test_categories]
        
        return tests
    
    def _generic_test(self, framework: BGPTestFramework, test: TestCase) -> TestResult:
        result = TestResult(
            test_id=test.test_id,
            test_name=test.name,
            category=test.category,
            passed=False,
            expected_behavior=test.description,
            actual_behavior="Generic test - not implemented"
        )
        
        if not framework.connect():
            result.actual_behavior = "Failed to establish TCP connection"
            return result
        
        framework.disconnect()
        return result
    
    def _run_message_header_tests(self) -> List[TestResult]:
        results = []
        framework = self._create_framework()
        
        tests = [
            ("MH-001", "test_invalid_marker", "Invalid Marker", 
             lambda: self._send_malformed_open(lambda msg: bytearray(msg)[:16] + b'\x00' * 16 + msg[16:])),
            ("MH-003", "test_length_too_short", "Length < 19",
             lambda: self._send_raw_message(lambda: MARKER + struct.pack('!HB', 10, 1) + b'\x00' * 5)),
            ("MH-004", "test_length_too_large", "Length > 4096",
             lambda: self._send_raw_message(lambda: MARKER + struct.pack('!HB', 5000, 4))),
            ("MH-006", "test_invalid_type", "Invalid Type (0)",
             lambda: self._send_raw_message(lambda: MARKER + struct.pack('!HB', 19, 0))),
            ("MH-009", "test_open_length_short", "OPEN < 29",
             lambda: self._send_open_message(28)),
            ("MH-010", "test_update_length_short", "UPDATE < 23",
             lambda: self._send_update_message(22)),
            ("MH-011", "test_keepalive_wrong_length", "KEEPALIVE != 19",
             lambda: self._send_raw_message(lambda: MARKER + struct.pack('!HB', 25, 4))),
            ("MH-012", "test_notification_length_short", "NOTIFICATION < 21",
             lambda: self._send_raw_message(lambda: MARKER + struct.pack('!HB', 18, 3) + b'\x00\x00')),
        ]
        
        for test_id, test_name, desc, test_func in tests:
            result = TestResult(
                test_id=test_id,
                test_name=test_name,
                category=TestCategory.MESSAGE_HEADER,
                passed=False,
                expected_behavior=desc,
                actual_behavior=""
            )
            
            try:
                response = test_func()
                if response:
                    result.passed = True
                    result.actual_behavior = f"Response received ({len(response)} bytes)"
                else:
                    result.actual_behavior = "No response"
            except Exception as e:
                result.actual_behavior = f"Error: {str(e)}"
            
            results.append(result)
            self.logger.log("INFO", f"Test {test_id}: {result.actual_behavior}")
        
        return results
    
    def _send_malformed_open(self, modifier) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = build_open_message(self.config.source_as, self.config.hold_time,
                                  struct.unpack('!I', socket.inet_aton(self.config.bgp_id))[0])
        malicious = modifier(msg)
        framework.send_raw(malicious)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_open_message(self, length: int) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = build_open_message(self.config.source_as)
        malformed = MARKER[:16] + struct.pack('!HB', length, 1) + msg[19:][:length-19]
        framework.send_raw(malformed)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_message(self, length: int) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = MARKER + struct.pack('!HB', length, 2) + b'\x00' * (length - 19)
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_raw_message(self, msg_func) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = msg_func()
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _run_open_message_tests(self) -> List[TestResult]:
        results = []
        
        tests = [
            ("OP-001", "Version 0", lambda: self._send_open_with_version(0)),
            ("OP-002", "Version 3", lambda: self._send_open_with_version(3)),
            ("OP-003", "Version 5", lambda: self._send_open_with_version(5)),
            ("OP-005", "Hold Time 1", lambda: self._send_open_with_hold_time(1)),
            ("OP-006", "Hold Time 2", lambda: self._send_open_with_hold_time(2)),
            ("OP-008", "BGP ID 0.0.0.0", lambda: self._send_open_with_bgp_id('0.0.0.0')),
            ("OP-009", "BGP ID 224.0.0.1", lambda: self._send_open_with_bgp_id('224.0.0.1')),
        ]
        
        for test_id, desc, test_func in tests:
            result = TestResult(
                test_id=test_id,
                test_name=desc,
                category=TestCategory.OPEN_MESSAGE,
                passed=False,
                expected_behavior=f"RFC 4271: {desc}",
                actual_behavior=""
            )
            
            try:
                response = test_func()
                if response and len(response) >= 21:
                    result.passed = True
                    result.actual_behavior = f"NOTIFICATION: code={response[19]}, subcode={response[20]}"
                    result.details = {'error_code': response[19], 'error_subcode': response[20]}
                else:
                    result.actual_behavior = "No NOTIFICATION received"
            except Exception as e:
                result.actual_behavior = f"Error: {str(e)}"
            
            results.append(result)
            self.logger.log("INFO", f"Test {test_id}: {result.actual_behavior}")
        
        return results
    
    def _send_open_with_version(self, version: int) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        bgp_id = struct.unpack('!I', socket.inet_aton(self.config.bgp_id))[0]
        data = struct.pack('!BHHI', version, self.config.source_as, 180, bgp_id)
        data += struct.pack('!B', 0)
        msg = MARKER + struct.pack('!HB', 29, 1) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_open_with_hold_time(self, hold_time: int) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        bgp_id = struct.unpack('!I', socket.inet_aton(self.config.bgp_id))[0]
        data = struct.pack('!BHHI', 4, self.config.source_as, hold_time, bgp_id)
        data += struct.pack('!B', 0)
        msg = MARKER + struct.pack('!HB', 29, 1) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_open_with_bgp_id(self, bgp_id: str) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        bgp_id_val = struct.unpack('!I', socket.inet_aton(bgp_id))[0]
        data = struct.pack('!BHHI', 4, self.config.source_as, 180, bgp_id_val)
        data += struct.pack('!B', 0)
        msg = MARKER + struct.pack('!HB', 29, 1) + data
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _run_update_message_tests(self) -> List[TestResult]:
        results = []
        
        tests = [
            ("UP-001", "Missing ORIGIN", lambda: self._send_update_without_origin()),
            ("UP-002", "Missing AS_PATH", lambda: self._send_update_without_aspath()),
            ("UP-003", "Missing NEXT_HOP", lambda: self._send_update_without_nexthop()),
            ("UP-004", "Invalid ORIGIN Value", lambda: self._send_update_with_invalid_origin()),
            ("UP-005", "Malformed AS_PATH", lambda: self._send_update_with_malformed_aspath()),
            ("UP-008", "NEXT_HOP 0.0.0.0", lambda: self._send_update_with_invalid_nexthop()),
            ("UP-011", "Attribute Length Error", lambda: self._send_update_with_attr_length_error()),
            ("UP-012", "Duplicate Attribute", lambda: self._send_update_with_duplicate_attr()),
        ]
        
        for test_id, desc, test_func in tests:
            result = TestResult(
                test_id=test_id,
                test_name=desc,
                category=TestCategory.UPDATE_MESSAGE,
                passed=False,
                expected_behavior=f"RFC 4271: {desc}",
                actual_behavior=""
            )
            
            try:
                response = test_func()
                if response and len(response) >= 21:
                    result.passed = True
                    result.actual_behavior = f"NOTIFICATION: code={response[19]}, subcode={response[20]}"
                    result.details = {'error_code': response[19], 'error_subcode': response[20]}
                else:
                    result.actual_behavior = "No NOTIFICATION received"
            except Exception as e:
                result.actual_behavior = f"Error: {str(e)}"
            
            results.append(result)
            self.logger.log("INFO", f"Test {test_id}: {result.actual_behavior}")
        
        return results
    
    def _send_update_without_origin(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = self._build_update_with_attrs([
            create_as_path_attribute([self.config.source_as]),
            create_next_hop_attribute(self.config.bgp_id)
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_without_aspath(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = self._build_update_with_attrs([
            create_origin_attribute(ORIGIN_TYPES['IGP']),
            create_next_hop_attribute(self.config.bgp_id)
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_without_nexthop(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = self._build_update_with_attrs([
            create_origin_attribute(ORIGIN_TYPES['IGP']),
            create_as_path_attribute([self.config.source_as])
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_with_invalid_origin(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        invalid_origin = PathAttribute(PATH_ATTRIBUTE_TYPES['ORIGIN'], 0x40, bytes([3]))
        msg = self._build_update_with_attrs([
            invalid_origin,
            create_as_path_attribute([self.config.source_as]),
            create_next_hop_attribute(self.config.bgp_id)
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_with_malformed_aspath(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        malformed_aspath = PathAttribute(PATH_ATTRIBUTE_TYPES['AS_PATH'], 0x40, bytes([2, 10]) + b'\x00' * 5)
        msg = self._build_update_with_attrs([
            create_origin_attribute(ORIGIN_TYPES['IGP']),
            malformed_aspath,
            create_next_hop_attribute(self.config.bgp_id)
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_with_invalid_nexthop(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = self._build_update_with_attrs([
            create_origin_attribute(ORIGIN_TYPES['IGP']),
            create_as_path_attribute([self.config.source_as]),
            create_next_hop_attribute('0.0.0.0')
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_with_attr_length_error(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        wrong_length_origin = PathAttribute(PATH_ATTRIBUTE_TYPES['ORIGIN'], 0x40, bytes([0, 0]))
        msg = self._build_update_with_attrs([
            wrong_length_origin,
            create_as_path_attribute([self.config.source_as]),
            create_next_hop_attribute(self.config.bgp_id)
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _send_update_with_duplicate_attr(self) -> Optional[bytes]:
        framework = self._create_framework()
        if not framework.connect():
            return None
        
        msg = self._build_update_with_attrs([
            create_origin_attribute(ORIGIN_TYPES['IGP']),
            create_as_path_attribute([self.config.source_as]),
            create_next_hop_attribute(self.config.bgp_id),
            create_origin_attribute(ORIGIN_TYPES['EGP'])
        ])
        framework.send_raw(msg)
        response = framework.receive_raw()
        framework.disconnect()
        return response
    
    def _build_update_with_attrs(self, attrs: List[PathAttribute], nlri: Optional[List] = None) -> bytes:
        path_attr_data = b''
        for attr in attrs:
            path_attr_data += attr.serialize()
        
        nlri_data = b''
        if nlri:
            for prefix, length in nlri:
                ip = ipaddress.ip_network(f"{prefix}/{length}", strict=False)
                nlri_data += bytes([length]) + ip.network_address.packed[:(length + 7) // 8]
        
        withdrawn_len = struct.pack('!H', 0)
        path_attr_len = struct.pack('!H', len(path_attr_data))
        data = withdrawn_len + path_attr_len + path_attr_data + nlri_data
        msg = MARKER + struct.pack('!HB', 19 + len(data), 2) + data
        return msg
    
    def run_all_tests(self) -> List[TestResult]:
        all_results = []
        
        category_handlers = {
            'message_header': self._run_message_header_tests,
            'open_message': self._run_open_message_tests,
            'update_message': self._run_update_message_tests,
        }
        
        if not self.config.test_categories:
            for handler in category_handlers.values():
                all_results.extend(handler())
        else:
            for cat in self.config.test_categories:
                if cat in category_handlers:
                    all_results.extend(category_handlers[cat]())
        
        self.results = all_results
        return all_results
    
    def get_summary(self) -> Dict[str, Any]:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        
        by_category = {}
        for result in self.results:
            cat = result.category.value
            if cat not in by_category:
                by_category[cat] = {'total': 0, 'passed': 0, 'failed': 0}
            by_category[cat]['total'] += 1
            if result.passed:
                by_category[cat]['passed'] += 1
            else:
                by_category[cat]['failed'] += 1
        
        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'pass_rate': f"{(passed/total*100):.1f}%" if total > 0 else "0%",
            'by_category': by_category,
            'target': f"{self.config.target_host}:{self.config.target_port}",
            'source_as': self.config.source_as
        }
    
    def generate_report(self) -> str:
        summary = self.get_summary()
        lines = [
            "=" * 80,
            "BGPv4 Adversarial Test Report",
            "=" * 80,
            f"Target: {summary['target']}",
            f"Source AS: {summary['source_as']}",
            "-" * 80,
            f"Total Tests: {summary['total']}",
            f"Passed: {summary['passed']}",
            f"Failed: {summary['failed']}",
            f"Pass Rate: {summary['pass_rate']}",
            "-" * 80,
            "Results by Category:",
        ]
        
        for cat, stats in summary['by_category'].items():
            lines.append(f"  {cat}: {stats['passed']}/{stats['total']} passed")
        
        lines.append("-" * 80)
        lines.append("Detailed Results:")
        
        for result in self.results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(f"  [{status}] {result.test_id}: {result.test_name}")
            lines.append(f"         Expected: {result.expected_behavior}")
            lines.append(f"         Actual: {result.actual_behavior}")
        
        return "\n".join(lines)
    
    def save_results(self, filepath: str, format: str = 'json'):
        import json
        
        data = {
            'summary': self.get_summary(),
            'results': [asdict(r) for r in self.results],
            'logs': self.logger.get_log()
        }
        
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format == 'yaml':
            with open(filepath, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
        
        logger.info(f"Results saved to {filepath}")


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def create_config_from_args(args) -> TestConfiguration:
    return TestConfiguration(
        target_host=args.target,
        target_port=args.port,
        source_as=args.as_number,
        source_ip=args.source_ip,
        bgp_id=args.bgp_id,
        hold_time=args.hold_time,
        timeout=args.timeout,
        test_categories=args.categories,
        test_ids=args.test_ids,
        delay_between_tests=args.delay,
        retry_count=args.retry,
        verbose=args.verbose,
        output_format=args.format,
        output_file=args.output
    )


def main():
    parser = argparse.ArgumentParser(
        description='BGPv4 Adversarial Test Framework - RFC 4271',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1 --as-number 65001
  %(prog)s --target 10.0.0.1 --port 179 --as-number 65001 --categories message_header open_message
  %(prog)s --target 192.168.1.1 --config config.yaml
  %(prog)s --target 192.168.1.1 --test-ids MH-001 MH-002 MH-003 --output results.json
        """
    )
    
    parser.add_argument('--target', '-t', required=True, help='Target BGP peer IP address')
    parser.add_argument('--port', '-p', type=int, default=179, help='BGP port (default: 179)')
    parser.add_argument('--as-number', '-a', type=int, default=65001, help='Source AS number')
    parser.add_argument('--source-ip', type=str, default='0.0.0.1', help='Source IP address')
    parser.add_argument('--bgp-id', type=str, default='10.0.0.1', help='BGP Identifier')
    parser.add_argument('--hold-time', type=int, default=180, help='Hold time in seconds')
    parser.add_argument('--timeout', type=float, default=5.0, help='Connection timeout in seconds')
    
    parser.add_argument('--categories', nargs='+', 
                       choices=['message_header', 'open_message', 'update_message', 
                               'attribute', 'fsm', 'timing', 'security'],
                       help='Test categories to run')
    parser.add_argument('--test-ids', nargs='+', help='Specific test IDs to run')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between tests')
    parser.add_argument('--retry', type=int, default=1, help='Number of retries')
    
    parser.add_argument('--config', '-c', type=str, help='YAML configuration file')
    parser.add_argument('--output', '-o', type=str, help='Output file for results')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.config:
        config_dict = load_config(args.config)
        args_dict = vars(args)
        args_dict.update(config_dict)
    
    config = create_config_from_args(args)
    
    logger.info(f"Starting BGPv4 adversarial tests against {config.target_host}:{config.target_port}")
    logger.info(f"Source AS: {config.source_as}")
    
    runner = TestRunner(config)
    
    try:
        results = runner.run_all_tests()
        
        print("\n" + runner.generate_report())
        
        if config.output_file:
            runner.save_results(config.output_file, config.output_format)
        
        summary = runner.get_summary()
        sys.exit(0 if summary['failed'] == 0 else 1)
        
    except KeyboardInterrupt:
        logger.warning("Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
