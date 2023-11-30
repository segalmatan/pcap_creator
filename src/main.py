import argparse
import json
import datetime

import mac
import tcpipv4

from dataclasses import dataclass
from typing import Dict
from random import randint

from simulation import Simulation
from pcap import Pcap


_DEFAULT_WINDOW_SIZE = 64128
JSON_START_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass
class NetworkEntity:
    mac: str
    ip: str
    port: int
    window: int


class ConvSimulation(Simulation):
    """
    Simulate data over TCP over IPv4 over ethernet
    """
    DEFAULT_TTL = 64

    def __init__(self, start_timestamp: int, ping_ms: int, ping_deviation_ms: int, entities: Dict[str, NetworkEntity]):
        super().__init__(start_timestamp, ping_ms, ping_deviation_ms)
        self._entities = entities

        self._current_ip_ids = {}
        self._current_seq_nums = {}

        for entity in self._entities.keys():
            for other_entity in self._entities.keys():
                self._current_ip_ids[(entity, other_entity)] = randint(1, 2**16-1)
                self._current_seq_nums[(entity, other_entity)] = randint(1, 2**32-1)

    def _create_packet_pair(self, sender: str, target: str, data: bytes):
        current_ip_id = self._current_ip_ids[(sender, target)]
        current_seq_num = self._current_seq_nums[(sender, target)]
        current_ack_num = self._current_seq_nums[(target, sender)]

        sender = self._entities[sender]
        target = self._entities[target]

        packet = tcpipv4.Packet(
            sender.ip, sender.port,
            target.ip, target.port,
            current_ip_id, self.DEFAULT_TTL,
            current_seq_num, current_ack_num,
            sender.window,
            data=data
        )

        ack_packet = packet.get_ack_packet(target.window)
        ack_num = ack_packet._tcp_packet._ack_num # TODO: Getting the ack number here and returning it is a temporary hack

        packet = mac.Packet(sender.mac, target.mac, mac.IPV4_ETHERTYPE, packet.build())
        ack_packet = mac.Packet(target.mac, sender.mac, mac.IPV4_ETHERTYPE, ack_packet.build())

        return packet, ack_packet, ack_num

    def simulate_message(self, sender: str, target: str, data: bytes, delay: int=0):
        packet, ack_packet, ack_num = self._create_packet_pair(sender, target, data)

        self.simulate_data(packet.build(), delay)
        self.simulate_data(ack_packet.build())

        self._current_ip_ids[(sender, target)] += 1
        self._current_seq_nums[(sender, target)] = ack_num

    def to_pcap(self):
        result = Pcap()
        for timestamp, data in self.records():
            result.add_record(timestamp, data)

        return result


def json_to_pcap(conversation_dict: Dict) -> Pcap:
    # TODO: have a ping matrix for each entity pair
    _SIMULATION_PING_MS = 40
    _SIMULATION_PING_MS_DIVIATION = 10

    entities = dict()
    for key, data in conversation_dict["entities"].items():
        entities[key] = NetworkEntity(data["mac"], data["ip"], data["port"], _DEFAULT_WINDOW_SIZE) # TODO: Set window

    start_timestamp_ms = int(datetime.datetime.strptime(
        conversation_dict["start_time_utc"],
        JSON_START_TIME_FORMAT
    ).replace(tzinfo=datetime.timezone.utc).timestamp()) * 1000
    simulation = ConvSimulation(start_timestamp_ms, _SIMULATION_PING_MS, _SIMULATION_PING_MS_DIVIATION, entities)

    for message in conversation_dict["messages"]:
        delay_ms = message.get("delay_ms", 0)
        delay_ms += message.get("delay_sec", 0) * 1000
        delay_ms += message.get("delay_min", 0) * 60 * 1000

        simulation.simulate_message(
            message["sender"],
            message["target"],
            message["data"].encode(),
            delay_ms
        )

    return simulation.to_pcap()


def main():
    parser = argparse.ArgumentParser(description="Create a PCAP from a json describing network packets")
    parser.add_argument("json_path", type=str, help="Packet description file")
    parser.add_argument("pcap_path", type=str, help="Generated PCAP path")

    args = parser.parse_args()

    pcap = json_to_pcap(json.load(open(args.json_path, "rb")))
    open(args.pcap_path, "wb").write(pcap.build())


if __name__ == "__main__":
    main()