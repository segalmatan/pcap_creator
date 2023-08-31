from construct import \
    Const, Struct, GreedyRange, this, \
    Int32ul, Int16ul, Byte


LINKTYPE_USER0 = 147
LINKTYPE_ETHERNET = 1


class Pcap:
    _MAGIC = 0xA1B2C3D4
    _MAJOR_VERSION = 2
    _MINOR_VERSION = 4

    _RECORD_STRUCT = Struct(
        "timestamp_sec" / Int32ul, # UNIX epoch time
        "timestamp_ms" / Int32ul, # miliseconds offset to timestamp_sec
        "captured_length" / Int32ul, # number of octets of packet saved in file
        "original_length" / Int32ul, # actual length of packet
        "data" / Byte[this.captured_length]
    )

    _STRUCT = Struct(
        "magic" / Const(_MAGIC, Int32ul),
        "major_version" / Const(_MAJOR_VERSION, Int16ul),
        "minor_version" / Const(_MINOR_VERSION, Int16ul),
        "reserved1" / Const(0, Int32ul),
        "reserved2" / Const(0, Int32ul),
        "snap_length" / Int32ul, # Max length of captured packets, in octets
        "link_type" / Int32ul,
        "records" / GreedyRange(_RECORD_STRUCT),
    )

    def __init__(self, link_type=LINKTYPE_ETHERNET):
        self._link_type = link_type
        self._records = []

    def add_record(self, unix_epoch_ms, data) -> None:
        """
        :param unix_epoch_ms: Time since the UNIX epoch of when the record was sent
        :type unix_epoch_ms: int
        :param data: Raw contents of the packet
        :type data: bytes
        """
        self._records.append({
            "timestamp_sec": unix_epoch_ms // 1000,
            "timestamp_ms": unix_epoch_ms % 1000,
            "captured_length": len(data),
            "original_length": len(data),
            "data": data
        })

    def build(self) -> bytes:
        return self._STRUCT.build({
            "snap_length": 0,
            "link_type": self._link_type,
            "records": self._records
        })