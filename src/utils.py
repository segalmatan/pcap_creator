from array import array
from socket import ntohs, htons


def ones_complement_checksum(data: bytes) -> bytes:
    checksum = 0

    if len(data) % 2 != 0:
        data += b"\x00"

    for subword in array("H", data):
        checksum += ntohs(subword)
        checksum = (checksum + (checksum >> 16)) & 0xffff

    return htons(0xffff - checksum)