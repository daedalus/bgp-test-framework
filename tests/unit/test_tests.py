"""
Unit tests for BGP test cases
"""

from bgp_test_framework.assessments import (
    TestCategory,
    TestResult,
    BGPTestFramework,
    TestCase,
    MessageHeaderAssessments,
    OpenMessageAssessments,
    UpdateMessageAssessments,
    AttributeAssessments,
    FSMAssessments,
    TimingAssessments,
    SecurityAssessments,
    CommunitiesAssessments,
    LargeCommunitiesAssessments,
    MultiprotocolAssessments,
    RouteRefreshAssessments,
    MPLSLabelAssessments,
    NOPEERCommunityAssessments,
    RouteFlapDampingAssessments,
    ASNumberAssessments,
    VPNAssessments,
    CapabilitiesAssessments,
    RouteOscillationAssessments,
    TEST_CLASSES,
    ALL_TEST_CATEGORIES,
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


class TestMessageHeaderAssessments:
    def test_get_tests(self):
        tests = MessageHeaderAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.MESSAGE_HEADER for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in MessageHeaderAssessments.get_tests()}
        assert "MH-001" in tests
        assert "MH-003" in tests
        assert "MH-004" in tests
        assert "MH-006" in tests


class TestOpenMessageAssessments:
    def test_get_tests(self):
        tests = OpenMessageAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.OPEN_MESSAGE for t in tests)

    def test_version_tests_exist(self):
        tests = {t.test_id: t for t in OpenMessageAssessments.get_tests()}
        assert "OP-001" in tests
        assert "OP-002" in tests
        assert "OP-003" in tests

    def test_hold_time_tests_exist(self):
        tests = {t.test_id: t for t in OpenMessageAssessments.get_tests()}
        assert "OP-004" in tests
        assert "OP-005" in tests
        assert "OP-006" in tests


class TestUpdateMessageAssessments:
    def test_get_tests(self):
        tests = UpdateMessageAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.UPDATE_MESSAGE for t in tests)

    def test_mandatory_attribute_tests(self):
        tests = {t.test_id: t for t in UpdateMessageAssessments.get_tests()}
        assert "UP-001" in tests
        assert "UP-002" in tests
        assert "UP-003" in tests

    def test_origin_tests(self):
        tests = {t.test_id: t for t in UpdateMessageAssessments.get_tests()}
        assert "UP-004" in tests


class TestAttributeAssessments:
    def test_get_tests(self):
        tests = AttributeAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.ATTRIBUTE for t in tests)

    def test_as_path_tests(self):
        tests = {t.test_id: t for t in AttributeAssessments.get_tests()}
        assert "ATTR-001" in tests
        assert "ATTR-004" in tests


class TestFSMAssessments:
    def test_get_tests(self):
        tests = FSMAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.FSM for t in tests)

    def test_update_in_wrong_state_tests(self):
        tests = {t.test_id: t for t in FSMAssessments.get_tests()}
        assert "FSM-001" in tests
        assert "FSM-002" in tests


class TestTimingAssessments:
    def test_get_tests(self):
        tests = TimingAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.TIMING for t in tests)

    def test_keepalive_tests(self):
        tests = {t.test_id: t for t in TimingAssessments.get_tests()}
        assert "TIM-001" in tests
        assert "TIM-002" in tests


class TestSecurityAssessments:
    def test_get_tests(self):
        tests = SecurityAssessments.get_tests()
        assert len(tests) > 0
        assert all(t.category == TestCategory.SECURITY for t in tests)

    def test_collision_tests(self):
        tests = {t.test_id: t for t in SecurityAssessments.get_tests()}
        assert "SEC-001" in tests
        assert "SEC-002" in tests


class TestTestCategories:
    def test_all_categories_defined(self):
        assert len(TestCategory) == 55
        assert TestCategory.MESSAGE_HEADER.value == "message_header"
        assert TestCategory.OPEN_MESSAGE.value == "open_message"
        assert TestCategory.UPDATE_MESSAGE.value == "update_message"
        assert TestCategory.ATTRIBUTE.value == "attribute"
        assert TestCategory.FSM.value == "fsm"
        assert TestCategory.TIMING.value == "timing"
        assert TestCategory.SECURITY.value == "security"
        assert TestCategory.ROUTE_AGGREGATION.value == "route_aggregation"
        assert TestCategory.DECISION_PROCESS.value == "decision_process"
        assert TestCategory.KEEPALIVE_MESSAGE.value == "keepalive_message"
        assert TestCategory.NOTIFICATION_MESSAGE.value == "notification_message"
        assert TestCategory.VERSION_NEGOTIATION.value == "version_negotiation"
        assert TestCategory.CONNECTION_COLLISION.value == "connection_collision"
        assert TestCategory.MULTIPROTOCOL.value == "multiprotocol"
        assert TestCategory.ROUTE_REFLECTION.value == "route_reflection"
        assert TestCategory.BGP_LS.value == "bgp_ls"
        assert TestCategory.CONFEDERATION.value == "confederation"
        assert TestCategory.GRACEFUL_RESTART.value == "graceful_restart"
        assert TestCategory.ENHANCED_ROUTE_REFRESH.value == "enhanced_route_refresh"
        assert TestCategory.EXTENDED_MESSAGES.value == "extended_messages"
        assert TestCategory.ORF_FILTERING.value == "orf_filtering"
        assert TestCategory.DYNAMIC_CAPABILITY.value == "dynamic_capability"


class TestCommunitiesAssessments:
    def test_get_tests(self):
        tests = CommunitiesAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.COMMUNITIES for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in CommunitiesAssessments.get_tests()}
        assert "COMM-001" in tests
        assert "COMM-005" in tests
        assert "COMM-010" in tests


class TestLargeCommunitiesAssessments:
    def test_get_tests(self):
        tests = LargeCommunitiesAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.LARGE_COMMUNITIES for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in LargeCommunitiesAssessments.get_tests()}
        assert "LCOMM-001" in tests
        assert "LCOMM-005" in tests
        assert "LCOMM-010" in tests


class TestMultiprotocolAssessments:
    def test_get_tests(self):
        tests = MultiprotocolAssessments.get_tests()
        assert len(tests) == 8
        assert all(t.category == TestCategory.MULTIPROTOCOL for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in MultiprotocolAssessments.get_tests()}
        assert "MP-001" in tests
        assert "MP-004" in tests
        assert "MP-008" in tests


class TestRouteRefreshAssessments:
    def test_get_tests(self):
        tests = RouteRefreshAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.ROUTE_REFRESH for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in RouteRefreshAssessments.get_tests()}
        assert "RFR-001" in tests
        assert "RFR-005" in tests
        assert "RFR-010" in tests


class TestMPLSLabelAssessments:
    def test_get_tests(self):
        tests = MPLSLabelAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.MPLS_LABELS for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in MPLSLabelAssessments.get_tests()}
        assert "LABEL-001" in tests
        assert "LABEL-005" in tests
        assert "LABEL-010" in tests


class TestNOPEERCommunityAssessments:
    def test_get_tests(self):
        tests = NOPEERCommunityAssessments.get_tests()
        assert len(tests) == 5
        assert all(t.category == TestCategory.NOPEER for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in NOPEERCommunityAssessments.get_tests()}
        assert "NOPEER-001" in tests
        assert "NOPEER-003" in tests
        assert "NOPEER-005" in tests


class TestRouteFlapDampingAssessments:
    def test_get_tests(self):
        tests = RouteFlapDampingAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.ROUTE_FLAP_DAMPING for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in RouteFlapDampingAssessments.get_tests()}
        assert "DAMP-001" in tests
        assert "DAMP-005" in tests
        assert "DAMP-010" in tests


class TestASNumberAssessments:
    def test_get_tests(self):
        tests = ASNumberAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.AS_NUMBER for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in ASNumberAssessments.get_tests()}
        assert "AS-001" in tests
        assert "AS-005" in tests
        assert "AS-010" in tests


class TestVPNAssessments:
    def test_get_tests(self):
        tests = VPNAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.VPN for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in VPNAssessments.get_tests()}
        assert "VPN-001" in tests
        assert "VPN-005" in tests
        assert "VPN-010" in tests


class TestCapabilitiesAssessments:
    def test_get_tests(self):
        tests = CapabilitiesAssessments.get_tests()
        assert len(tests) == 8
        assert all(t.category == TestCategory.CAPABILITIES for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in CapabilitiesAssessments.get_tests()}
        assert "CAP-001" in tests
        assert "CAP-004" in tests
        assert "CAP-008" in tests


class TestRouteOscillationAssessments:
    def test_get_tests(self):
        tests = RouteOscillationAssessments.get_tests()
        assert len(tests) == 5
        assert all(t.category == TestCategory.ROUTE_OSCILLATION for t in tests)

    def test_specific_tests_exist(self):
        tests = {t.test_id: t for t in RouteOscillationAssessments.get_tests()}
        assert "OSCIL-001" in tests
        assert "OSCIL-003" in tests
        assert "OSCIL-005" in tests


class TestTESTCLASSESConstant:
    def test_all_test_classes_registered(self):
        assert "message_header" in TEST_CLASSES
        assert "open_message" in TEST_CLASSES
        assert "update_message" in TEST_CLASSES
        assert "communities" in TEST_CLASSES
        assert "large_communities" in TEST_CLASSES
        assert "multiprotocol" in TEST_CLASSES
        assert "route_refresh" in TEST_CLASSES
        assert "mpls_labels" in TEST_CLASSES
        assert "nopeer" in TEST_CLASSES
        assert "route_flap_damping" in TEST_CLASSES
        assert "as_number" in TEST_CLASSES
        assert "vpn" in TEST_CLASSES
        assert "capabilities" in TEST_CLASSES
        assert "route_oscillation" in TEST_CLASSES


class TestALLTESTCATEGORIESConstant:
    def test_all_categories_included(self):
        expected_categories = [
            "message_header",
            "open_message",
            "update_message",
            "attribute",
            "fsm",
            "timing",
            "security",
            "communities",
            "large_communities",
            "multiprotocol",
            "route_refresh",
            "mpls_labels",
            "nopeer",
            "route_flap_damping",
            "as_number",
            "vpn",
            "capabilities",
            "route_oscillation",
        ]
        for cat in expected_categories:
            assert cat in ALL_TEST_CATEGORIES


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


class TestCeaseNotificationAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import CeaseNotificationAssessments

        tests = CeaseNotificationAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.CEASE_NOTIFICATION for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import CeaseNotificationAssessments

        tests = {t.test_id: t for t in CeaseNotificationAssessments.get_tests()}
        assert "CEASE-001" in tests
        assert "CEASE-005" in tests
        assert "CEASE-008" in tests


class TestIPv6VPNAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import IPv6VPNAssessments

        tests = IPv6VPNAssessments.get_tests()
        assert len(tests) >= 9
        assert all(t.category == TestCategory.IPV6_VPN for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import IPv6VPNAssessments

        tests = {t.test_id: t for t in IPv6VPNAssessments.get_tests()}
        assert "V6VPN-001" in tests
        assert "V6VPN-002" in tests


class TestGTSMAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import GTSMAssessments

        tests = GTSMAssessments.get_tests()
        assert len(tests) == 8
        assert all(t.category == TestCategory.GTSM for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import GTSMAssessments

        tests = {t.test_id: t for t in GTSMAssessments.get_tests()}
        assert "GTSM-255" in tests
        assert "GTSM-001" in tests
        assert "GTSM-003" in tests


class TestFlowSpecAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import FlowSpecAssessments

        tests = FlowSpecAssessments.get_tests()
        assert len(tests) >= 28
        assert all(t.category == TestCategory.FLOW_SPEC for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import FlowSpecAssessments

        tests = {t.test_id: t for t in FlowSpecAssessments.get_tests()}
        assert "FSPEC-001" in tests
        assert "FSPEC-133" in tests
        assert "FSPEC-134" in tests


class TestNewTESTCLASSESConstant:
    def test_new_categories_registered(self):
        assert "cease_notification" in TEST_CLASSES
        assert "ipv6_vpn" in TEST_CLASSES
        assert "gtsm" in TEST_CLASSES
        assert "flow_spec" in TEST_CLASSES
        assert "ipv6_extended_community" in TEST_CLASSES
        assert "rpki_router" in TEST_CLASSES
        assert "origin_validation" in TEST_CLASSES
        assert "as0_processing" in TEST_CLASSES
        assert "bgp_ls" in TEST_CLASSES


class TestIPv6ExtCommunityAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import IPv6ExtCommunityAssessments

        tests = IPv6ExtCommunityAssessments.get_tests()
        assert len(tests) >= 7
        assert all(t.category == TestCategory.IPV6_EXTENDED_COMMUNITY for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import IPv6ExtCommunityAssessments

        tests = {t.test_id: t for t in IPv6ExtCommunityAssessments.get_tests()}
        assert "V6EC-0002" in tests
        assert "V6EC-0003" in tests
        assert "V6EC-001" in tests


class TestRPKIRouterAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import RPKIRouterAssessments

        tests = RPKIRouterAssessments.get_tests()
        assert len(tests) >= 10
        assert all(t.category == TestCategory.RPKI_ROUTER for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import RPKIRouterAssessments

        tests = {t.test_id: t for t in RPKIRouterAssessments.get_tests()}
        assert "RPKI-000" in tests
        assert "RPKI-001" in tests
        assert "RPKI-004" in tests
        assert "RPKI-006" in tests


class TestOriginValidationAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import OriginValidationAssessments

        tests = OriginValidationAssessments.get_tests()
        assert len(tests) >= 7
        assert all(t.category == TestCategory.ORIGIN_VALIDATION for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import OriginValidationAssessments

        tests = {t.test_id: t for t in OriginValidationAssessments.get_tests()}
        assert "OV-000" in tests
        assert "OV-001" in tests
        assert "OV-002" in tests
        assert "OV-003" in tests


class TestAS0Assessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import AS0Assessments

        tests = AS0Assessments.get_tests()
        assert len(tests) >= 10
        assert all(t.category == TestCategory.AS0_PROCESSING for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import AS0Assessments

        tests = {t.test_id: t for t in AS0Assessments.get_tests()}
        assert "AS0-001" in tests
        assert "AS0-002" in tests
        assert "AS0-003" in tests


class TestBGPLinkStateAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import BGPLinkStateAssessments

        tests = BGPLinkStateAssessments.get_tests()
        assert len(tests) >= 10
        assert all(t.category == TestCategory.BGP_LS_NLRI for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import BGPLinkStateAssessments

        tests = {t.test_id: t for t in BGPLinkStateAssessments.get_tests()}
        assert "BGPLS-NLRI-01" in tests
        assert "BGPLS-NLRI-02" in tests
        assert "BGPLS-001" in tests
        assert "BGPLS-002" in tests


class TestTestCategoryNewEntries:
    def test_new_categories_defined(self):
        assert TestCategory.IPV6_EXTENDED_COMMUNITY.value == "ipv6_extended_community"
        assert TestCategory.RPKI_ROUTER.value == "rpki_router"
        assert TestCategory.ORIGIN_VALIDATION.value == "origin_validation"
        assert TestCategory.AS0_PROCESSING.value == "as0_processing"
        assert TestCategory.BGP_LS_NLRI.value == "bgp_ls_nlri"
        assert TestCategory.BLACKHOLE_COMMUNITY.value == "blackhole_community"
        assert TestCategory.ADMIN_SHUTDOWN.value == "admin_shutdown"
        assert TestCategory.MPLS_LABEL_BINDING.value == "mpls_label_binding"
        assert TestCategory.LARGE_COMMUNITY_USAGE.value == "large_community_usage"
        assert TestCategory.DATACENTER_BGP.value == "datacenter_bgp"


class TestBlackholeCommunityAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import BlackholeCommunityAssessments

        tests = BlackholeCommunityAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.BLACKHOLE_COMMUNITY for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import BlackholeCommunityAssessments

        tests = {t.test_id: t for t in BlackholeCommunityAssessments.get_tests()}
        assert "BH-001" in tests
        assert "BH-004" in tests
        assert "BH-010" in tests


class TestAdminShutdownAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import AdminShutdownAssessments

        tests = AdminShutdownAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.ADMIN_SHUTDOWN for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import AdminShutdownAssessments

        tests = {t.test_id: t for t in AdminShutdownAssessments.get_tests()}
        assert "AS-001" in tests
        assert "AS-003" in tests
        assert "AS-010" in tests


class TestMPLSLabelBindingAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import MPLSLabelBindingAssessments

        tests = MPLSLabelBindingAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.MPLS_LABEL_BINDING for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import MPLSLabelBindingAssessments

        tests = {t.test_id: t for t in MPLSLabelBindingAssessments.get_tests()}
        assert "MLB-001" in tests
        assert "MLB-003" in tests
        assert "MLB-005" in tests


class TestLargeCommunityUsageAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import LargeCommunityUsageAssessments

        tests = LargeCommunityUsageAssessments.get_tests()
        assert len(tests) >= 11
        assert all(t.category == TestCategory.LARGE_COMMUNITY_USAGE for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import LargeCommunityUsageAssessments

        tests = {t.test_id: t for t in LargeCommunityUsageAssessments.get_tests()}
        assert "LCU-FUNC-01" in tests
        assert "LCU-FUNC-04" in tests
        assert "LCU-001" in tests
        assert "LCU-004" in tests


class TestDataCenterBGPAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import DataCenterBGPAssessments

        tests = DataCenterBGPAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.DATACENTER_BGP for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import DataCenterBGPAssessments

        tests = {t.test_id: t for t in DataCenterBGPAssessments.get_tests()}
        assert "DCB-001" in tests
        assert "DCB-004" in tests
        assert "DCB-007" in tests


class TestNewTESTCLASSESConstantRFCs:
    def test_new_categories_registered(self):
        assert "blackhole_community" in TEST_CLASSES
        assert "admin_shutdown" in TEST_CLASSES
        assert "mpls_label_binding" in TEST_CLASSES
        assert "large_community_usage" in TEST_CLASSES
        assert "datacenter_bgp" in TEST_CLASSES


class TestGracefulShutdownAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import GracefulShutdownAssessments

        tests = GracefulShutdownAssessments.get_tests()
        assert len(tests) == 10
        assert all(t.category == TestCategory.GRACEFUL_SHUTDOWN for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import GracefulShutdownAssessments

        tests = {t.test_id: t for t in GracefulShutdownAssessments.get_tests()}
        assert "GSD-001" in tests
        assert "GSD-005" in tests
        assert "GSD-010" in tests


class TestEVPNNVOAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import EVPNNVOAssessments

        tests = EVPNNVOAssessments.get_tests()
        assert len(tests) >= 10
        assert all(t.category == TestCategory.EVPN_NVO for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import EVPNNVOAssessments

        tests = {t.test_id: t for t in EVPNNVOAssessments.get_tests()}
        assert "EVPN-TUN-08" in tests
        assert "EVPN-001" in tests
        assert "EVPN-003" in tests


class TestSegmentRoutingAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import SegmentRoutingAssessments

        tests = SegmentRoutingAssessments.get_tests()
        assert len(tests) >= 8
        assert all(t.category == TestCategory.SEGMENT_ROUTING for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import SegmentRoutingAssessments

        tests = {t.test_id: t for t in SegmentRoutingAssessments.get_tests()}
        assert "SR-ALGO-0" in tests
        assert "SR-ALGO-1" in tests
        assert "SR-001" in tests


class TestIRBAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import IRBAssessments

        tests = IRBAssessments.get_tests()
        assert len(tests) >= 7
        assert all(t.category == TestCategory.EVPN_IRB for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import IRBAssessments

        tests = {t.test_id: t for t in IRBAssessments.get_tests()}
        assert "IRB-SYMMETRIC-001" in tests
        assert "IRB-ANYCAST-001" in tests


class TestEVPNIPPrefixAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import EVPNIPPrefixAssessments

        tests = EVPNIPPrefixAssessments.get_tests()
        assert len(tests) >= 11
        assert all(t.category == TestCategory.EVPN_IP_PREFIX for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import EVPNIPPrefixAssessments

        tests = {t.test_id: t for t in EVPNIPPrefixAssessments.get_tests()}
        assert "RT5-IPv4-001" in tests
        assert "RT5-IPv6-001" in tests
        assert "RT5-RECURSIVE-001" in tests


class TestBGPRoleAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import BGPRoleAssessments

        tests = BGPRoleAssessments.get_tests()
        assert len(tests) >= 15
        assert all(t.category == TestCategory.BGP_ROLE for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import BGPRoleAssessments

        tests = {t.test_id: t for t in BGPRoleAssessments.get_tests()}
        assert "ROLE-PROVIDER" in tests
        assert "ROLE-CUSTOMER" in tests
        assert "ROLE-OTC-001" in tests


class TestSRv6BGPOverlayAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import SRv6BGPOverlayAssessments

        tests = SRv6BGPOverlayAssessments.get_tests()
        assert len(tests) >= 17
        assert all(t.category == TestCategory.SRV6_BGP_OVERLAY for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import SRv6BGPOverlayAssessments

        tests = {t.test_id: t for t in SRv6BGPOverlayAssessments.get_tests()}
        assert "SRV6-L3_SERVICE-001" in tests
        assert "SRV6-SID-END_DX4" in tests
        assert "SRV6-L3VPN-001" in tests


class TestSRPolicyAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import SRPolicyAssessments

        tests = SRPolicyAssessments.get_tests()
        assert len(tests) >= 18
        assert all(t.category == TestCategory.SR_POLICY for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import SRPolicyAssessments

        tests = {t.test_id: t for t in SRPolicyAssessments.get_tests()}
        assert "SRPOL-SEG-A" in tests
        assert "SRPOL-IDENT-001" in tests
        assert "SRPOL-BSID-001" in tests


class TestBGP_LS_UpdatedAssessments:
    def test_get_tests(self):
        from bgp_test_framework.assessments import BGP_LS_UpdatedAssessments

        tests = BGP_LS_UpdatedAssessments.get_tests()
        assert len(tests) >= 17
        assert all(t.category == TestCategory.BGP_LS_UPDATED for t in tests)

    def test_specific_tests_exist(self):
        from bgp_test_framework.assessments import BGP_LS_UpdatedAssessments

        tests = {t.test_id: t for t in BGP_LS_UpdatedAssessments.get_tests()}
        assert "BGPLS-NODE" in tests
        assert "BGPLS-LINK" in tests
        assert "BGPLS-ATTR-001" in tests


class TestNewTESTCLASSESEVPNSR:
    def test_new_categories_registered(self):
        assert "graceful_shutdown" in TEST_CLASSES
        assert "evpn_nvo" in TEST_CLASSES
        assert "segment_routing" in TEST_CLASSES
        assert "evpn_irb" in TEST_CLASSES
        assert "evpn_ip_prefix" in TEST_CLASSES
        assert "bgp_role" in TEST_CLASSES
        assert "srv6_bgp_overlay" in TEST_CLASSES
        assert "sr_policy" in TEST_CLASSES
        assert "bgp_ls_updated" in TEST_CLASSES
