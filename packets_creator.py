import struct
import socket


class PacketsCreator:
    @staticmethod
    def create_tcp_packet(start_host, finish_host, seq, flags=0):
        tcp_package = struct.pack(
            "!HHIIBBHHH", 1329, 80, seq, 0, 5 << 4, flags, 1024, 0, 0
        )

        pseudo_ip_header = struct.pack(
            "!4s4sHH",
            socket.inet_aton(start_host),
            socket.inet_aton(finish_host),
            socket.IPPROTO_TCP,
            len(tcp_package),
        )

        checksum = PacketsCreator._check_sum(pseudo_ip_header + tcp_package)
        result_package = (
            tcp_package[:16] + struct.pack("H", checksum) + tcp_package[18:]
        )

        return result_package

    @staticmethod
    def _check_sum(msg):
        s = 0
        even_or_odd_len_msg = len(msg) % 2
        for i in range(0, len(msg), 2):
            s += ((msg[i]) + ((msg[i + 1]) << 8) +
                  (msg[i + 1]) * even_or_odd_len_msg)
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s
