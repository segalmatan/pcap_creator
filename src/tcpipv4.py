import ipv4
import tcp

from simulation import Simulation


_IP_PROTOCOL_TCP = 6
_IP_TCP_PSEUDO_HEADER_OFFSET_START = 12
_IP_TCP_PSEUDO_HEADER_OFFSET_END = 20 # TODO: This value is made up, check it


class Packet:
    @classmethod
    def _ipv4_pseudo_header(cls, ip_packet):
        return ip_packet.build()[_IP_TCP_PSEUDO_HEADER_OFFSET_START:_IP_TCP_PSEUDO_HEADER_OFFSET_END]

    def __init__(
        self,
        source_ip, source_port,
        dest_ip, dest_port,
        ip_identification, ttl,
        seq_num, ack_num, window,
        cwr=False, ece=False, ack=False, psh=False, rst=False, syn=False, fin=False,
        data=b""
    ):
        # NOTE: IPv4 original values are needed for the TCP packet checksum (pseudo header)
        self._ip_packet = ipv4.Packet(
            source_ip, dest_ip, ip_identification, ttl,
            _IP_PROTOCOL_TCP, data=tcp.Packet(data=data).build()
        )

        self._tcp_packet = tcp.Packet(
            source_port, dest_port, seq_num, ack_num, window,
            cwr, ece, ack, psh, rst, syn, fin,
            self._ipv4_pseudo_header(self._ip_packet), data
        )

        self._ip_packet._data = self._tcp_packet.build()

    def get_ack_packet(self, remote_window=0):
        tcp_ack_packet = self._tcp_packet.get_ack_response(window=remote_window)

        ip_packet = ipv4.Packet(
            self._ip_packet._dest_address,
            self._ip_packet._source_address,
            self._ip_packet._identification,
            self._ip_packet._ttl,
            _IP_PROTOCOL_TCP,
            tcp_ack_packet.build()
        )

        tcp_ack_packet.set_pseudo_header(self._ipv4_pseudo_header(ip_packet))

        ip_packet._data = tcp_ack_packet.build()

        result = Packet("0.0.0.0", 0, "0.0.0.0", 0, 0, 0, 0, 0, 0)
        result._ip_packet = ip_packet
        result._tcp_packet = tcp_ack_packet
        return result

    def build(self) -> bytes:
        return self._ip_packet.build()
