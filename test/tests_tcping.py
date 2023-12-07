import unittest
import socket
from packets_creator import PacketsCreator
from unittest.mock import patch
from tcping import tcping, establish_connection, port_knocking, get_ip
from statistic_helper import StatisticHelper


class MyScriptTest(unittest.TestCase):
    def setUp(self):
        self.ip_target_host = "77.88.55.242"
        self.ip_target_host_with_timeout = "823.100.0.5"
        self.packet = PacketsCreator.create_tcp_packet(
            f"{get_ip()}", self.ip_target_host, 0, 2
        )
        self.syn_packet = PacketsCreator.create_tcp_packet(
            f"{get_ip()}", self.ip_target_host, 245167, 2
        )
        self.timeout = 2

    def test_tcping_success(self):
        with patch("socket.socket") as mock_sock:
            with patch.object(
                    PacketsCreator,
                    "create_tcp_packet",
                    return_value=self.packet
            ):
                mock_sock.sendto(self.packet, (self.ip_target_host, 80))
                mock_sock.recvfrom(16384)
                sh = StatisticHelper()
                tcping(self.ip_target_host, sh, self.timeout)
                self.assertEqual(mock_sock.call_count, 2)
                mock_sock.recvfrom.assert_called_once()
                mock_sock.sendto.assert_called_once_with(
                    self.packet, (self.ip_target_host, 80)
                )

    def test_tcping_timeout(self):
        with (patch("socket.socket") as mock_sock):
            with patch.object(
                    PacketsCreator,
                    "create_tcp_packet",
                    return_value=self.packet
            ):
                with patch("builtins.print") as mock_print:
                    mock_sock.sendto(
                        self.packet, (self.ip_target_host_with_timeout, 80)
                    )
                    mock_sock \
                        .return_value \
                        .__enter__ \
                        .return_value \
                        .recvfrom \
                        .return_value = \
                        (
                            None
                        )
                    mock_sock \
                        .return_value \
                        .__enter__ \
                        .return_value \
                        .recvfrom \
                        .side_effect = \
                        (
                            socket.timeout
                        )
                    sh = StatisticHelper()
                    tcping(self.ip_target_host_with_timeout, sh, self.timeout)
                    mock_print.assert_called_once_with(
                        f"No response from "
                        f"{self.ip_target_host_with_timeout}: timeout!"
                    )

    def test_establish_connection_success(self):
        data = (
            b"E\x00\x00,\x00\x00@\x008"
            b"\x06\xfcqMX7\xf2\xc0\xa8"
            b"\x00h\x00P\x051\xb1s[["
            b"\x00\x03\xbd\xb0`\x12"
            b"\xa5<\xdc\xad\x00\x00\x02\x04\x05\x82"
        )
        with patch("socket.socket") as mock_sock:
            with patch.object(
                    PacketsCreator,
                    "create_tcp_packet",
                    return_value=self.syn_packet
            ):
                with patch("random.randint") as mock_get_rnd_num:
                    mock_get_rnd_num.return_value = 245167
                    mock_get_rnd_num(0, 2966784)
                    mock_sock.sendto(
                        self.syn_packet,
                        (self.ip_target_host_with_timeout, 80)
                    )
                    mock_sock \
                        .return_value \
                        .__enter__ \
                        .return_value \
                        .recvfrom \
                        .return_value = \
                        (
                            data,
                            (f"{self.ip_target_host}", 0),
                        )
                    result = establish_connection(
                        self.ip_target_host,
                        80,
                        self.timeout
                    )
                    self.assertTrue(result)

    def test_establish_connection_fail(self):
        with patch("socket.socket") as mock_sock:
            with patch.object(
                    PacketsCreator,
                    "create_tcp_packet",
                    return_value=self.syn_packet
            ):
                mock_sock.sendto(
                    self.syn_packet,
                    (self.ip_target_host_with_timeout, 80)
                )
                mock_sock \
                    .return_value \
                    .__enter__ \
                    .return_value \
                    .recvfrom \
                    .side_effect = \
                    (
                        socket.timeout
                    )
                result = establish_connection(
                    self.ip_target_host_with_timeout, 80, self.timeout
                )
                self.assertFalse(result)

    def test_port_knocking(self):
        ports = [8000, 9000, 10000]
        with patch.object(
                PacketsCreator,
                "create_tcp_packet",
                return_value=self.packet
        ):
            with patch("time.sleep") as mock_sleep:
                port_knocking(ports, self.ip_target_host, 0, self.timeout)
                self.assertEqual(mock_sleep.call_count, len(ports))


if __name__ == "__main__":
    unittest.main()
