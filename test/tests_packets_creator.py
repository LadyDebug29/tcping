import unittest
from packets_creator import PacketsCreator


class TestPacketsCreator(unittest.TestCase):
    def setUp(self):
        self.start_host = "192.168.1.1"
        self.finish_host = "192.168.1.2"
        self.seq = 1
        self.flags = 0
        self.correct_tcp_packet = (
            b"\x051\x00P\x00\x00\x00\x01\x00\x00"
            b"\x00\x00P\x00\x04\x00#\x0f\x00\x00"
        )

    def test_create_tcp_packet(self):
        packet = PacketsCreator.create_tcp_packet(
            self.start_host, self.finish_host, self.seq, self.flags
        )
        self.assertEqual(self.correct_tcp_packet, packet)

    def test_check_sum(self):
        checksum = (PacketsCreator._PacketsCreator__check_sum(
            self.correct_tcp_packet
            )
        )
        self.assertEqual(28291, checksum)


if __name__ == "__main__":
    unittest.main()
