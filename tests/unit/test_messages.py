"""
Unit tests for BGP message parsing and construction
"""

import pytest
import struct
from bgp_test_framework.messages import (
    MARKER, BGPMessage, BGPOpenMessage, BGPUpdateMessage,
    BGPKeepaliveMessage, BGPNotificationMessage, PathAttribute,
    build_open_message, build_update_message, build_notification_message,
    build_keepalive_message, create_origin_attribute, create_as_path_attribute,
    create_next_hop_attribute, BGPHeaderParser
)
from bgp_test_framework.constants import (
    MESSAGE_TYPES, PATH_ATTRIBUTE_TYPES, ORIGIN_TYPES, AS_PATH_SEGMENT_TYPES
)


class TestBGPHeaderParser:
    def test_parse_valid_header(self):
        header = MARKER + struct.pack('!HB', 29, MESSAGE_TYPES['OPEN'])
        marker, length, msg_type = BGPHeaderParser.parse(header)
        assert marker == MARKER
        assert length == 29
        assert msg_type == MESSAGE_TYPES['OPEN']
    
    def test_parse_header_too_short(self):
        with pytest.raises(ValueError):
            BGPHeaderParser.parse(b'\x00' * 10)
    
    def test_parse_invalid_marker(self):
        header = b'\x00' * 16 + struct.pack('!HB', 29, MESSAGE_TYPES['OPEN'])
        with pytest.raises(ValueError):
            BGPHeaderParser.parse(header)
    
    def test_parse_invalid_length_too_short(self):
        header = MARKER + struct.pack('!HB', 10, MESSAGE_TYPES['OPEN'])
        with pytest.raises(ValueError):
            BGPHeaderParser.parse(header)
    
    def test_parse_invalid_length_too_large(self):
        header = MARKER + struct.pack('!HB', 5000, MESSAGE_TYPES['OPEN'])
        with pytest.raises(ValueError):
            BGPHeaderParser.parse(header)
    
    def test_parse_type(self):
        header = MARKER + struct.pack('!HB', 29, MESSAGE_TYPES['UPDATE'])
        msg_type = BGPHeaderParser.parse_type(header)
        assert msg_type == MESSAGE_TYPES['UPDATE']


class TestBGPOpenMessage:
    def test_open_message_serialize(self):
        msg = BGPOpenMessage(version=4, my_as=65001, hold_time=180, 
                            bgp_id=0x0A000001, optional_params=b'')
        data = msg.serialize()
        assert len(data) == 29
        assert data[0:16] == MARKER
        assert data[16:18] == struct.pack('!H', 29)
        assert data[18] == MESSAGE_TYPES['OPEN']
        assert data[19] == 4
        assert struct.unpack('!H', data[20:22])[0] == 65001
    
    def test_open_message_parse(self):
        msg = BGPOpenMessage(version=4, my_as=65001, hold_time=180,
                            bgp_id=0x0A000001)
        data = msg.serialize()
        parsed = BGPOpenMessage.parse(data[19:])
        assert parsed.version == 4
        assert parsed.my_as == 65001
        assert parsed.hold_time == 180
        assert parsed.bgp_id == 0x0A000001


class TestBGPUpdateMessage:
    def test_update_message_minimum_length(self):
        msg = BGPUpdateMessage()
        data = msg.serialize()
        assert len(data) == 23
    
    def test_update_message_with_nlri(self):
        msg = BGPUpdateMessage(
            withdrawn_routes=b'',
            path_attributes=b'',
            nlri=bytes([24, 192, 168, 1, 0])
        )
        data = msg.serialize()
        assert len(data) == 28


class TestBGPKeepaliveMessage:
    def test_keepalive_message_length(self):
        msg = BGPKeepaliveMessage()
        data = msg.serialize()
        assert len(data) == 19
    
    def test_keepalive_message_type(self):
        msg = BGPKeepaliveMessage()
        data = msg.serialize()
        assert data[18] == MESSAGE_TYPES['KEEPALIVE']


class TestBGPNotificationMessage:
    def test_notification_message(self):
        msg = BGPNotificationMessage(
            error_code=1,
            error_subcode=1,
            data=b''
        )
        data = msg.serialize()
        assert len(data) == 21
        assert data[18] == MESSAGE_TYPES['NOTIFICATION']
        assert data[19] == 1
        assert data[20] == 1
    
    def test_notification_message_parse(self):
        msg = BGPNotificationMessage(error_code=3, error_subcode=11, data=b'\x00\x01\x02')
        data = msg.serialize()
        parsed = BGPNotificationMessage.parse(data[19:])
        assert parsed.error_code == 3
        assert parsed.error_subcode == 11


class TestPathAttribute:
    def test_origin_attribute(self):
        attr = PathAttribute(PATH_ATTRIBUTE_TYPES['ORIGIN'], 0x40, bytes([0]))
        data = attr.serialize()
        assert data[0] == 0x40
        assert data[1] == PATH_ATTRIBUTE_TYPES['ORIGIN']
        assert data[2] == 1
        assert data[3] == 0
    
    def test_as_path_attribute(self):
        aspath_data = bytes([AS_PATH_SEGMENT_TYPES['AS_SEQUENCE'], 2]) + struct.pack('!HH', 65001, 65002)
        attr = PathAttribute(PATH_ATTRIBUTE_TYPES['AS_PATH'], 0x40, aspath_data)
        data = attr.serialize()
        assert data[0] == 0x40
        assert data[1] == PATH_ATTRIBUTE_TYPES['AS_PATH']
    
    def test_extended_length_attribute(self):
        attr = PathAttribute(1, 0x50, bytes([0]))
        data = attr.serialize()
        assert data[0] == 0x50
        assert data[2:4] == struct.pack('!H', 1)


class TestMessageBuilders:
    def test_build_open_message(self):
        msg = build_open_message(my_as=65001, hold_time=180)
        assert len(msg) == 29
        assert msg[0:16] == MARKER
        assert msg[18] == MESSAGE_TYPES['OPEN']
    
    def test_build_keepalive_message(self):
        msg = build_keepalive_message()
        assert len(msg) == 19
        assert msg[18] == MESSAGE_TYPES['KEEPALIVE']
    
    def test_build_notification_message(self):
        msg = build_notification_message(1, 1, b'')
        assert len(msg) == 21
        assert msg[18] == MESSAGE_TYPES['NOTIFICATION']


class TestAttributeCreators:
    def test_create_origin_attribute(self):
        attr = create_origin_attribute(ORIGIN_TYPES['IGP'])
        assert attr.attr_type == PATH_ATTRIBUTE_TYPES['ORIGIN']
        assert attr.value == bytes([ORIGIN_TYPES['IGP']])
    
    def test_create_as_path_attribute(self):
        attr = create_as_path_attribute([65001, 65002])
        assert attr.attr_type == PATH_ATTRIBUTE_TYPES['AS_PATH']
    
    def test_create_next_hop_attribute(self):
        attr = create_next_hop_attribute('192.168.1.1')
        assert attr.attr_type == PATH_ATTRIBUTE_TYPES['NEXT_HOP']


class TestMarkerConstant:
    def test_marker_length(self):
        assert len(MARKER) == 16
    
    def test_marker_all_ones(self):
        assert MARKER == b'\xff' * 16


class TestMessageTypes:
    def test_message_type_names(self):
        assert MESSAGE_TYPES['OPEN'] == 1
        assert MESSAGE_TYPES['UPDATE'] == 2
        assert MESSAGE_TYPES['NOTIFICATION'] == 3
        assert MESSAGE_TYPES['KEEPALIVE'] == 4
    
    def test_origin_types(self):
        assert ORIGIN_TYPES['IGP'] == 0
        assert ORIGIN_TYPES['EGP'] == 1
        assert ORIGIN_TYPES['INCOMPLETE'] == 2
    
    def test_as_path_segment_types(self):
        assert AS_PATH_SEGMENT_TYPES['AS_SET'] == 1
        assert AS_PATH_SEGMENT_TYPES['AS_SEQUENCE'] == 2
