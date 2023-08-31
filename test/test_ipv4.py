from src import ipv4


def main():
    packet = ipv4.Packet("1.1.1.1", "2.2.2.2", 0, b"hello")
    print(packet.build.hex())


if __name__ == "__main__":
    main()