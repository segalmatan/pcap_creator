from construct import Aligned, Struct, Bytes, Int16ub, GreedyBytes


IPV4_ETHERTYPE        = 0x0800
ARP_ETHERTYPE         = 0x0806
IPV6_ETHERTYPE        = 0x86DD
VLAN_ETHERTYPE        = 0x8100
LOOPBACK_ETHERTYPE    = 0x080E


class Packet:
    # Preamble, SFD and FCS are not included
    _STRUCT = Aligned(
        8,
        Struct(
            "destination_mac" / Bytes(6),
            "source_mac" / Bytes(6),
            "ether_type" / Int16ub,
            "data" / GreedyBytes
        )
    )

    @classmethod
    def _mac_string_to_bytes(cls, mac_string: str) -> bytes:
        mac_bytes = mac_string.split(":")
        if 6 != len(mac_bytes):
            raise ValueError("Too many MAC bytes")

        return bytes(int(x, base=16) for x in mac_bytes)

    def __init__(self, source_mac, dest_mac, ether_type, data=b""):
        self._source_mac = source_mac
        self._dest_mac = dest_mac
        self._ether_type = ether_type
        self._data = data

    def build(self) -> bytes:
        return self._STRUCT.build({
            "destination_mac": self._mac_string_to_bytes(self._dest_mac),
            "source_mac": self._mac_string_to_bytes(self._source_mac),
            "ether_type": self._ether_type,
            "data": self._data
        })