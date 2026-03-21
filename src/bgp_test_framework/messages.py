"""
BGP Message Parser and Builder
Implements RFC 4271 message formats
"""

import struct
import ipaddress
from typing import Optional, List, Tuple
from .constants import (
    MARKER,
    MESSAGE_TYPES,
    AS_PATH_SEGMENT_TYPES,
    AS_CONFED_PATH_SEGMENT_TYPES,
    PATH_ATTRIBUTE_FLAGS,
    PATH_ATTRIBUTE_TYPES,
)


class BGPMessage:
    def __init__(self, msg_type: int, data: bytes = b""):
        self.msg_type = msg_type
        self.data = data

    @property
    def marker(self) -> bytes:
        return MARKER

    @property
    def length(self) -> int:
        return 19 + len(self.data)

    def serialize(self) -> bytes:
        return self.marker + struct.pack("!HB", self.length, self.msg_type) + self.data


class BGPHeaderParser:
    @staticmethod
    def parse(data: bytes) -> Tuple[bytes, int, int]:
        if len(data) < 19:
            raise ValueError(f"Header too short: {len(data)} bytes")

        marker = data[:16]
        if marker != MARKER:
            raise ValueError(f"Invalid marker: expected all 0xFF, got {marker.hex()}")

        length = struct.unpack("!H", data[16:18])[0]
        msg_type = struct.unpack("!B", data[18:19])[0]

        if length < 19 or length > 4096:
            raise ValueError(f"Invalid message length: {length}")

        return marker, length, msg_type

    @staticmethod
    def parse_type(data: bytes) -> int:
        if len(data) < 19:
            raise ValueError("Header too short")
        return struct.unpack("!B", data[18:19])[0]


class BGPOpenMessage:
    def __init__(
        self,
        version: int = 4,
        my_as: int = 0,
        hold_time: int = 180,
        bgp_id: int = 0,
        optional_params: bytes = b"",
    ):
        self.version = version
        self.my_as = my_as
        self.hold_time = hold_time
        self.bgp_id = bgp_id
        self.optional_params = optional_params

    def serialize(self) -> bytes:
        data = struct.pack(
            "!BHHI", self.version, self.my_as, self.hold_time, self.bgp_id
        )
        data += struct.pack("!B", len(self.optional_params)) + self.optional_params
        return BGPMessage(MESSAGE_TYPES["OPEN"], data).serialize()

    @classmethod
    def parse(cls, data: bytes) -> "BGPOpenMessage":
        offset = 0
        if len(data) >= 19 and data[0:16] == MARKER:
            offset = 19
        if len(data) - offset < 10:
            raise ValueError(f"OPEN message too short: {len(data)} bytes")

        version = struct.unpack("!B", data[offset : offset + 1])[0]
        my_as = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
        hold_time = struct.unpack("!H", data[offset + 3 : offset + 5])[0]
        bgp_id = struct.unpack("!I", data[offset + 5 : offset + 9])[0]
        opt_param_len = struct.unpack("!B", data[offset + 9 : offset + 10])[0]
        optional_params = (
            data[offset + 10 : offset + 10 + opt_param_len]
            if opt_param_len > 0
            else b""
        )

        return cls(version, my_as, hold_time, bgp_id, optional_params)


class BGPUpdateMessage:
    def __init__(
        self,
        withdrawn_routes: bytes = b"",
        path_attributes: bytes = b"",
        nlri: bytes = b"",
    ):
        self.withdrawn_routes = withdrawn_routes
        self.path_attributes = path_attributes
        self.nlri = nlri

    @property
    def withdrawn_routes_length(self) -> int:
        return len(self.withdrawn_routes)

    @property
    def total_path_attribute_length(self) -> int:
        return len(self.path_attributes)

    def serialize(self) -> bytes:
        withdrawn_len = struct.pack("!H", self.withdrawn_routes_length)
        path_attr_len = struct.pack("!H", self.total_path_attribute_length)
        data = (
            withdrawn_len
            + self.withdrawn_routes
            + path_attr_len
            + self.path_attributes
            + self.nlri
        )
        return BGPMessage(MESSAGE_TYPES["UPDATE"], data).serialize()

    @classmethod
    def parse(cls, data: bytes) -> "BGPUpdateMessage":
        if len(data) < 4:
            raise ValueError("UPDATE message too short")

        withdrawn_len = struct.unpack("!H", data[0:2])[0]
        path_attr_len = struct.unpack(
            "!H", data[2 + withdrawn_len : 4 + withdrawn_len]
        )[0]

        withdrawn_routes = data[2 : 2 + withdrawn_len]
        path_attributes = data[4 + withdrawn_len : 4 + withdrawn_len + path_attr_len]
        nlri = data[4 + withdrawn_len + path_attr_len :]

        return cls(withdrawn_routes, path_attributes, nlri)


class BGPKeepaliveMessage:
    def serialize(self) -> bytes:
        return BGPMessage(MESSAGE_TYPES["KEEPALIVE"], b"").serialize()

    @classmethod
    def parse(cls, data: bytes) -> "BGPKeepaliveMessage":
        return cls()


class BGPNotificationMessage:
    def __init__(self, error_code: int, error_subcode: int = 0, data: bytes = b""):
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = data

    def serialize(self) -> bytes:
        data = struct.pack("!BB", self.error_code, self.error_subcode) + self.data
        return BGPMessage(MESSAGE_TYPES["NOTIFICATION"], data).serialize()

    @classmethod
    def parse(cls, data: bytes) -> "BGPNotificationMessage":
        if len(data) < 2:
            raise ValueError("NOTIFICATION message too short")

        error_code = struct.unpack("!B", data[0:1])[0]
        error_subcode = struct.unpack("!B", data[1:2])[0]
        notification_data = data[2:] if len(data) > 2 else b""

        return cls(error_code, error_subcode, notification_data)


class BGPRouteRefreshMessage:
    def __init__(self, afi: int, safi: int, reserved: int = 0):
        self.afi = afi
        self.safi = safi
        self.reserved = reserved

    def serialize(self) -> bytes:
        data = struct.pack("!HBB", self.afi, self.reserved, self.safi)
        return BGPMessage(MESSAGE_TYPES["ROUTE_REFRESH"], data).serialize()

    @classmethod
    def parse(cls, data: bytes) -> "BGPRouteRefreshMessage":
        if len(data) < 4:
            raise ValueError("ROUTE_REFRESH message too short")

        offset = 0
        if len(data) >= 19 and data[0:16] == MARKER:
            offset = 19

        if len(data) - offset < 4:
            raise ValueError("ROUTE_REFRESH message too short")

        afi = struct.unpack("!H", data[offset : offset + 2])[0]
        reserved = data[offset + 2]
        safi = data[offset + 3]

        return cls(afi, safi, reserved)


class PathAttribute:
    def __init__(self, attr_type: int, flags: int, value: bytes):
        self.attr_type = attr_type
        self.flags = flags
        self.value = value

    @property
    def length(self) -> int:
        if self.flags & PATH_ATTRIBUTE_FLAGS["EXTENDED_LENGTH"]:
            return len(self.value)
        return len(self.value) if len(self.value) <= 255 else 255

    def serialize(self) -> bytes:
        header = struct.pack("!BB", self.flags, self.attr_type)
        if self.flags & PATH_ATTRIBUTE_FLAGS["EXTENDED_LENGTH"]:
            header += struct.pack("!H", len(self.value))
        else:
            header += struct.pack("!B", len(self.value))
        return header + self.value

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Tuple["PathAttribute", int]:
        flags = data[offset]
        attr_type = data[offset + 1]

        if flags & PATH_ATTRIBUTE_FLAGS["EXTENDED_LENGTH"]:
            length = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            value = data[offset + 4 : offset + 4 + length]
            header_len = 4
        else:
            length = data[offset + 2]
            value = data[offset + 3 : offset + 3 + length]
            header_len = 3

        return cls(attr_type, flags, value), offset + header_len + length


class NLRIPrefix:
    def __init__(self, prefix: str, length: int):
        self.prefix = prefix
        self.length = length

    def serialize(self) -> bytes:
        import ipaddress

        ip = ipaddress.ip_address(self.prefix)
        prefix_bytes = ip.packed
        num_octets = (self.length + 7) // 8
        padded = prefix_bytes[:num_octets] + b"\x00" * (
            num_octets - len(prefix_bytes[:num_octets])
        )
        return bytes([self.length]) + padded

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Tuple["NLRIPrefix", int]:
        length = data[offset]
        num_octets = (length + 7) // 8
        prefix_bytes = data[offset + 1 : offset + 1 + num_octets]
        prefix = ipaddress.ip_network(
            f"{prefix_bytes[:num_octets].hex()}/{length}", strict=False
        )
        return cls(str(prefix.network_address), length), offset + 1 + num_octets


def build_open_message(
    my_as: int,
    hold_time: int = 180,
    bgp_id: int = 0,
    capabilities: Optional[List[Tuple[int, bytes]]] = None,
) -> bytes:
    import ipaddress

    if bgp_id == 0:
        bgp_id = int(ipaddress.ip_address("0.0.0.1"))

    optional_params = b""
    if capabilities:
        for cap_code, cap_value in capabilities:
            cap_data = struct.pack("!BB", cap_code, len(cap_value)) + cap_value
            optional_params += struct.pack("!B", 2)
            optional_params += struct.pack("!B", len(cap_data))
            optional_params += cap_data

    msg = BGPOpenMessage(
        version=4,
        my_as=my_as,
        hold_time=hold_time,
        bgp_id=bgp_id,
        optional_params=optional_params,
    )
    return msg.serialize()


def build_update_message(
    withdrawn_prefixes: Optional[List[Tuple[str, int]]] = None,
    path_attributes: Optional[List[PathAttribute]] = None,
    nlri_prefixes: Optional[List[Tuple[str, int]]] = None,
) -> bytes:
    import ipaddress

    withdrawn_data = b""
    if withdrawn_prefixes:
        for prefix, length in withdrawn_prefixes:
            ip = ipaddress.ip_network(f"{prefix}/{length}", strict=False)
            withdrawn_data += (
                bytes([length]) + ip.network_address.packed[: (length + 7) // 8]
            )

    path_attr_data = b""
    if path_attributes:
        for attr in path_attributes:
            path_attr_data += attr.serialize()

    nlri_data = b""
    if nlri_prefixes:
        for prefix, length in nlri_prefixes:
            ip = ipaddress.ip_network(f"{prefix}/{length}", strict=False)
            nlri_data += (
                bytes([length]) + ip.network_address.packed[: (length + 7) // 8]
            )

    msg = BGPUpdateMessage(withdrawn_data, path_attr_data, nlri_data)
    return msg.serialize()


def build_notification_message(
    error_code: int, error_subcode: int = 0, data: bytes = b""
) -> bytes:
    msg = BGPNotificationMessage(error_code, error_subcode, data)
    return msg.serialize()


def build_keepalive_message() -> bytes:
    msg = BGPKeepaliveMessage()
    return msg.serialize()


def build_route_refresh_message(afi: int, safi: int, reserved: int = 0) -> bytes:
    msg = BGPRouteRefreshMessage(afi, safi, reserved)
    return msg.serialize()


def create_origin_attribute(origin_type: int) -> PathAttribute:
    return PathAttribute(PATH_ATTRIBUTE_TYPES["ORIGIN"], 0x40, bytes([origin_type]))


def create_as_path_attribute(
    as_numbers: List[int], segment_type: int = 2
) -> PathAttribute:
    if segment_type == AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"]:
        data = bytes([segment_type, len(as_numbers)]) + b"".join(
            struct.pack("!H", asn) for asn in as_numbers
        )
    else:
        data = bytes([segment_type, len(as_numbers)]) + b"".join(
            struct.pack("!H", asn) for asn in as_numbers
        )
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_next_hop_attribute(next_hop: str) -> PathAttribute:
    import ipaddress

    ip = ipaddress.ip_address(next_hop)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["NEXT_HOP"], 0x40, ip.packed)


def create_multi_exit_disc_attribute(med: int) -> PathAttribute:
    return PathAttribute(
        PATH_ATTRIBUTE_TYPES["MULTI_EXIT_DISC"], 0x80, struct.pack("!I", med)
    )


def create_local_pref_attribute(local_pref: int) -> PathAttribute:
    return PathAttribute(
        PATH_ATTRIBUTE_TYPES["LOCAL_PREF"], 0x40, struct.pack("!I", local_pref)
    )


def create_aggregator_attribute(as_number: int, router_id: str) -> PathAttribute:
    import ipaddress

    ip = ipaddress.ip_address(router_id)
    return PathAttribute(
        PATH_ATTRIBUTE_TYPES["AGGREGATOR"],
        0xC0,
        struct.pack("!H", as_number) + ip.packed,
    )


def create_atomic_aggregate_attribute() -> PathAttribute:
    return PathAttribute(PATH_ATTRIBUTE_TYPES["ATOMIC_AGGREGATE"], 0x40, b"")


def create_unrecognized_well_known_attribute() -> PathAttribute:
    return PathAttribute(8, 0x40, b"\x00\x01")


def create_as_path_with_loop(as_numbers: List[int], own_as: int) -> PathAttribute:
    path_with_loop = as_numbers + [own_as] + as_numbers[:2]
    data = bytes(
        [AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"], len(path_with_loop)]
    ) + b"".join(struct.pack("!H", asn) for asn in path_with_loop)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_as_path_with_confed(
    segment_type: int, as_numbers: List[int]
) -> PathAttribute:
    data = bytes([segment_type, len(as_numbers)]) + b"".join(
        struct.pack("!H", asn) for asn in as_numbers
    )
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_invalid_nexthop_attribute(nexthop: str) -> PathAttribute:
    import ipaddress

    ip = ipaddress.ip_address(nexthop)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["NEXT_HOP"], 0x40, ip.packed)


def create_local_pref_on_ebgp(local_pref: int) -> PathAttribute:
    return PathAttribute(
        PATH_ATTRIBUTE_TYPES["LOCAL_PREF"], 0x40, struct.pack("!I", local_pref)
    )


def create_malformed_aggregator_attribute() -> PathAttribute:
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AGGREGATOR"], 0xC0, b"\x00\x01\x00")


def create_as_set_attribute(as_numbers: List[int]) -> PathAttribute:
    data = bytes([AS_PATH_SEGMENT_TYPES["AS_SET"], len(as_numbers)]) + b"".join(
        struct.pack("!H", asn) for asn in as_numbers
    )
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_as_path_overflow(as_count: int) -> PathAttribute:
    as_numbers = list(range(1, as_count + 1))
    return create_as_path_attribute(as_numbers, AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"])


def create_invalid_segment_type_aspath(
    segment_type: int, as_numbers: List[int]
) -> PathAttribute:
    data = bytes([segment_type, len(as_numbers)]) + b"".join(
        struct.pack("!H", asn) for asn in as_numbers
    )
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_duplicate_attribute(attr: PathAttribute) -> bytes:
    return attr.serialize() + attr.serialize()


def create_confed_sequence_attribute(member_as_numbers: List[int]) -> PathAttribute:
    data = bytes(
        [AS_CONFED_PATH_SEGMENT_TYPES["AS_CONFED_SEQUENCE"], len(member_as_numbers)]
    ) + b"".join(struct.pack("!H", asn) for asn in member_as_numbers)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_confed_set_attribute(member_as_numbers: List[int]) -> PathAttribute:
    data = bytes(
        [AS_CONFED_PATH_SEGMENT_TYPES["AS_CONFED_SET"], len(member_as_numbers)]
    ) + b"".join(struct.pack("!H", asn) for asn in member_as_numbers)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, data)


def create_confed_sequence_with_as_sequence(
    member_as_numbers: List[int], external_as_numbers: List[int]
) -> PathAttribute:
    confed_data = bytes(
        [AS_CONFED_PATH_SEGMENT_TYPES["AS_CONFED_SEQUENCE"], len(member_as_numbers)]
    ) + b"".join(struct.pack("!H", asn) for asn in member_as_numbers)
    as_data = bytes(
        [AS_PATH_SEGMENT_TYPES["AS_SEQUENCE"], len(external_as_numbers)]
    ) + b"".join(struct.pack("!H", asn) for asn in external_as_numbers)
    return PathAttribute(PATH_ATTRIBUTE_TYPES["AS_PATH"], 0x40, confed_data + as_data)
