from construct import \
    Const, Struct, BitStruct, \
    Flag, Int8ub, Int16ub, Int32ub, \
    GreedyBytes

from utils import ones_complement_checksum


DEFAULT_WINDOW_SIZE = 1500


class Packet:
    _HEADER = Struct(
        "source_port" / Int16ub,
        "destination_port" / Int16ub,
        "seq_number" / Int32ub,
        "ack_number" / Int32ub,
        "DO" / Int8ub, # NOTE: Manually adjust to a nibble value (the consecutive nibble is 0) to keep construct usage simple
        "flags" / BitStruct(
            "CWR" / Flag,
            "ECE" / Flag,
            "URG" / Const(False, Flag), # NOTE: Urgent Pointer not supported
            "ACK" / Flag,
            "PSH" / Flag,
            "RST" / Flag,
            "SYN" / Flag,
            "FIN" / Flag,
        ),
        "window" / Int16ub,
        "checksum" / Int16ub,
        "urgent_pointer" / Const(0, Int16ub), # NOTE: Urgent Pointer not supported
    )

    _STRUCT = Struct(
        "header" / _HEADER,
        "data" / GreedyBytes
    )

    def __init__(
        self,
        source_port=0, dest_port=0, seq_num=0, ack_num=0, window=DEFAULT_WINDOW_SIZE,
        cwr=False, ece=False, ack=False, psh=False, rst=False, syn=False, fin=False,
        pseudo_header_data=b"",
        data=b""
    ):
        self._pseudo_header_data = pseudo_header_data
        self._source_port = source_port
        self._dest_port = dest_port
        self._seq_num = seq_num
        self._ack_num = ack_num
        self._cwr = cwr
        self._ece = ece
        self._ack = ack
        self._psh = psh
        self._rst = rst
        self._syn = syn
        self._fin = fin
        self._window = window
        self._data = data

    def set_pseudo_header(self, raw_pseudo_header):
        self._pseudo_header_data = raw_pseudo_header

    def get_ack_response(self, **kwargs):
        return Packet(
            self._dest_port, self._source_port,
            self._seq_num, self._seq_num + int(self._syn or self._fin) + len(self._data),
            ack=True, **kwargs
        )

    def build(self) -> bytes:
        packet = {
            "header": {
                "source_port": self._source_port,
                "destination_port": self._dest_port,
                "seq_number": self._seq_num,
                "ack_number": self._ack_num,
                "DO": (self._HEADER.sizeof() // 4) << 4, # NOTE: Higher nibble is DO, lower nibble is 0
                "flags": {
                    "CWR": self._cwr,
                    "ECE": self._ece,
                    "ACK": self._ack,
                    "PSH": self._psh,
                    "RST": self._rst,
                    "SYN": self._syn,
                    "FIN": self._fin,
                },
                "window": self._window,
                "checksum": 0,
            },
            "data": self._data
        }

        # NOTE: checksum is calculated over the packet data and the pseudo header (ip header, etc..)
        packet["header"]["checksum"] = ones_complement_checksum(
            self._pseudo_header_data + self._STRUCT.build(packet)
        )

        return self._STRUCT.build(packet)
