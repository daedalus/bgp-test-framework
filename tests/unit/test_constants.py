"""
Unit tests for BGP constants
"""

from bgp_test_framework.constants import (
    MARKER,
    BGP_PORT,
    MESSAGE_TYPES,
    MESSAGE_TYPE_NAMES,
    MESSAGE_MIN_LENGTHS,
    ORIGIN_TYPES,
    AS_PATH_SEGMENT_TYPES,
    PATH_ATTRIBUTE_FLAGS,
    PATH_ATTRIBUTE_TYPES,
    NOTIFICATION_ERROR_CODES,
    MESSAGE_HEADER_ERROR_SUBCODES,
    OPEN_MESSAGE_ERROR_SUBCODES,
    UPDATE_MESSAGE_ERROR_SUBCODES,
    WELL_KNOWN_MANDATORY_ATTRIBUTES,
    AFI_VALUES,
    SAFI_VALUES,
    CAPABILITY_CODES,
    BGP_FSM_STATES,
)


class TestMarker:
    def test_marker_is_16_bytes(self):
        assert len(MARKER) == 16

    def test_marker_all_ones(self):
        assert MARKER == b"\xff" * 16


class TestBGPPort:
    def test_bgp_port(self):
        assert BGP_PORT == 179


class TestMessageTypes:
    def test_all_types_defined(self):
        assert MESSAGE_TYPES["OPEN"] == 1
        assert MESSAGE_TYPES["UPDATE"] == 2
        assert MESSAGE_TYPES["NOTIFICATION"] == 3
        assert MESSAGE_TYPES["KEEPALIVE"] == 4

    def test_type_names_consistency(self):
        for name, code in MESSAGE_TYPES.items():
            assert MESSAGE_TYPE_NAMES[code] == name


class TestMessageMinLengths:
    def test_all_min_lengths_defined(self):
        assert MESSAGE_MIN_LENGTHS[1] == 29
        assert MESSAGE_MIN_LENGTHS[2] == 23
        assert MESSAGE_MIN_LENGTHS[3] == 21
        assert MESSAGE_MIN_LENGTHS[4] == 19


class TestOriginTypes:
    def test_all_origin_types(self):
        assert ORIGIN_TYPES["IGP"] == 0
        assert ORIGIN_TYPES["EGP"] == 1
        assert ORIGIN_TYPES["INCOMPLETE"] == 2

    def test_valid_origin_range(self):
        for value in ORIGIN_TYPES.values():
            assert 0 <= value <= 2


class TestASPathSegmentTypes:
    def test_all_segment_types(self):
        assert AS_PATH_SEGMENT_TYPES["AS_SET"] == 1
        assert AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"] == 2


class TestPathAttributeFlags:
    def test_flag_bits(self):
        assert PATH_ATTRIBUTE_FLAGS["OPTIONAL"] == 0x80
        assert PATH_ATTRIBUTE_FLAGS["TRANSITIVE"] == 0x40
        assert PATH_ATTRIBUTE_FLAGS["PARTIAL"] == 0x20
        assert PATH_ATTRIBUTE_FLAGS["EXTENDED_LENGTH"] == 0x10

    def test_flags_are_non_overlapping(self):
        flags = list(PATH_ATTRIBUTE_FLAGS.values())
        for i, f1 in enumerate(flags):
            for f2 in flags[i + 1 :]:
                assert f1 & f2 == 0


class TestPathAttributeTypes:
    def test_all_attribute_types(self):
        assert PATH_ATTRIBUTE_TYPES["ORIGIN"] == 1
        assert PATH_ATTRIBUTE_TYPES["AS_PATH"] == 2
        assert PATH_ATTRIBUTE_TYPES["NEXT_HOP"] == 3
        assert PATH_ATTRIBUTE_TYPES["MULTI_EXIT_DISC"] == 4
        assert PATH_ATTRIBUTE_TYPES["LOCAL_PREF"] == 5
        assert PATH_ATTRIBUTE_TYPES["ATOMIC_AGGREGATE"] == 6
        assert PATH_ATTRIBUTE_TYPES["AGGREGATOR"] == 7


class TestNotificationErrorCodes:
    def test_all_error_codes(self):
        assert NOTIFICATION_ERROR_CODES["MESSAGE_HEADER_ERROR"] == 1
        assert NOTIFICATION_ERROR_CODES["OPEN_MESSAGE_ERROR"] == 2
        assert NOTIFICATION_ERROR_CODES["UPDATE_MESSAGE_ERROR"] == 3
        assert NOTIFICATION_ERROR_CODES["HOLD_TIMER_EXPIRED"] == 4
        assert NOTIFICATION_ERROR_CODES["FINITE_STATE_MACHINE_ERROR"] == 5
        assert NOTIFICATION_ERROR_CODES["CEASE"] == 6


class TestMessageHeaderErrorSubcodes:
    def test_all_subcodes(self):
        assert MESSAGE_HEADER_ERROR_SUBCODES["CONNECTION_NOT_SYNCHRONIZED"] == 1
        assert MESSAGE_HEADER_ERROR_SUBCODES["BAD_MESSAGE_LENGTH"] == 2
        assert MESSAGE_HEADER_ERROR_SUBCODES["BAD_MESSAGE_TYPE"] == 3


class TestOpenMessageErrorSubcodes:
    def test_all_subcodes(self):
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNSUPPORTED_VERSION_NUMBER"] == 1
        assert OPEN_MESSAGE_ERROR_SUBCODES["BAD_PEER_AS"] == 2
        assert OPEN_MESSAGE_ERROR_SUBCODES["BAD_BGP_IDENTIFIER"] == 3
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNSUPPORTED_OPTIONAL_PARAMETER"] == 4
        assert OPEN_MESSAGE_ERROR_SUBCODES["UNACCEPTABLE_HOLD_TIME"] == 6


class TestUpdateMessageErrorSubcodes:
    def test_all_subcodes(self):
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MALFORMED_ATTRIBUTE_LIST"] == 1
        assert UPDATE_MESSAGE_ERROR_SUBCODES["UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE"] == 2
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MISSING_WELL_KNOWN_ATTRIBUTE"] == 3
        assert UPDATE_MESSAGE_ERROR_SUBCODES["ATTRIBUTE_FLAGS_ERROR"] == 4
        assert UPDATE_MESSAGE_ERROR_SUBCODES["ATTRIBUTE_LENGTH_ERROR"] == 5
        assert UPDATE_MESSAGE_ERROR_SUBCODES["INVALID_ORIGIN_ATTRIBUTE"] == 6
        assert UPDATE_MESSAGE_ERROR_SUBCODES["INVALID_NEXT_HOP_ATTRIBUTE"] == 8
        assert UPDATE_MESSAGE_ERROR_SUBCODES["OPTIONAL_ATTRIBUTE_ERROR"] == 9
        assert UPDATE_MESSAGE_ERROR_SUBCODES["INVALID_NETWORK_FIELD"] == 10
        assert UPDATE_MESSAGE_ERROR_SUBCODES["MALFORMED_AS_PATH"] == 11


class TestWellKnownMandatoryAttributes:
    def test_well_known_mandatory(self):
        assert 1 in WELL_KNOWN_MANDATORY_ATTRIBUTES
        assert 2 in WELL_KNOWN_MANDATORY_ATTRIBUTES
        assert 3 in WELL_KNOWN_MANDATORY_ATTRIBUTES


class TestAFIValues:
    def test_afi_values(self):
        assert AFI_VALUES["IPv4"] == 1
        assert AFI_VALUES["IPv6"] == 2


class TestSAFIValues:
    def test_safi_values(self):
        assert SAFI_VALUES["UNICAST"] == 1
        assert SAFI_VALUES["MULTICAST"] == 2


class TestCapabilityCodes:
    def test_capability_codes(self):
        assert CAPABILITY_CODES["MULTIPROTOCOL_EXTENSIONS"] == 1
        assert CAPABILITY_CODES["ROUTE_REFRESH"] == 2
        assert CAPABILITY_CODES["FOUR_OCTET_AS_NUMBER"] == 65


class TestBGPFSMStates:
    def test_fsm_states(self):
        assert BGP_FSM_STATES["Idle"] == 0
        assert BGP_FSM_STATES["Connect"] == 1
        assert BGP_FSM_STATES["Active"] == 2
        assert BGP_FSM_STATES["OpenSent"] == 3
        assert BGP_FSM_STATES["OpenConfirm"] == 4
        assert BGP_FSM_STATES["Established"] == 5

    def test_fsm_state_count(self):
        assert len(BGP_FSM_STATES) == 6
