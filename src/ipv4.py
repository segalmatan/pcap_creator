from ipaddress import IPv4Address

from construct import \
    Const, Struct, BitStruct, \
    Flag, Nibble, Int8ub, Int16ub, BitsInteger, \
    Bytes, GreedyBytes

from utils import ones_complement_checksum


_TYPICAL_MTU = 1500


class Packet:
    _HEADER = Struct(
        BitStruct(
            "version" / Const(4, Nibble),
            "IHL" / Const(5, Nibble) # Options are not supported so size is fixed
        ),
        "TOS" / Const(0, Int8ub), # Type of Service
        "total_length" / Int16ub,
        "identification" / Int16ub,
        BitStruct( # NOTE: Fragmentation not supported
            Const(False, Flag), # NOTE: Reserved by the protocol
            "DF" / Const(True, Flag),
            "MF" / Const(False, Flag),
            "fragment_offset" / Const(0, BitsInteger(13)),
        ),
        "TTL" / Int8ub,
        "protocol" / Int8ub,
        "checksum" / Int16ub,
        "source_address" / Bytes(4),
        "destination_address" / Bytes(4),
        # NOTE: header options are not supported, but they should come here
    )

    _STRUCT = Struct(
        "header" / _HEADER,
        "data" / GreedyBytes
    )

    def __init__(self, source_address, dest_address, identification=0, ttl=64, protocol=0, data=b""):
        self._source_address = IPv4Address(source_address)
        self._dest_address = IPv4Address(dest_address)
        self._identification = identification
        self._ttl = ttl
        self._protocol = protocol
        self._header_checksum = 0
        self._data = data

        if len(self.build()) > _TYPICAL_MTU:
            raise ValueError("Packet size exceeds typical IPv4 MTU, fragmentation not supported")

    def build(self) -> bytes:
        packet = {
            "header": {
                "total_length": 0,
                "identification": self._identification,
                "TTL": self._ttl,
                "protocol": self._protocol,
                "checksum": 0,
                "source_address": self._source_address.packed,
                "destination_address": self._dest_address.packed,
            },
            "data": self._data
        }

        total_length = len(self._STRUCT.build(packet))
        packet["header"]["total_length"] = total_length
        packet["header"]["checksum"] = ones_complement_checksum(
            self._HEADER.build(packet["header"])
        )

        return self._STRUCT.build(packet)
