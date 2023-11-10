import socket
import sys
import unittest
from io import StringIO
from unittest.mock import patch
from main import get_statistics, tcping, port_knocking
from statistic_helper import StatisticHelper


class TCPingTestCase(unittest.TestCase):
    def setUp(self):
        self.sh = StatisticHelper()

    def test_get_statistics(self):
        output = StringIO()
        sys.stdout = output

        self.sh.number_packets_sent = 10
        self.sh.successed = 8
        get_statistics(self.sh)

        sys.stdout = sys.__stdout__
        self.assertEqual("10 packets transmitted, 8 received, 20% packet loss", output.getvalue().strip())

    @patch('socket.socket')
    def test_tcping_successful(self, mock_socket):
        with mock_socket.return_value as mock_sock:
            mock_sock.recv.return_value = b"Connected response"

            tcping("127.0.0.1", self.sh)

            self.assertEqual(1, mock_sock.sendto.call_count)
            self.assertEqual(1, self.sh.successed)

    @patch('socket.socket')
    def test_tcping_timeout(self, mock_socket):
        with mock_socket.return_value as mock_sock:
            mock_sock.recv.side_effect = socket.timeout("Timeout error")
            try:
                tcping("127.0.0.1", self.sh)
            except socket.timeout:
                pass

            self.assertEqual(1, mock_sock.sendto.call_count)
            self.assertEqual(0, self.sh.successed)

    @patch('socket.socket')
    def test_port_knocking(self, mock_socket):
        with mock_socket.return_value as mock_sock:

            port_knocking([49152, 62834, 52142], "127.0.0.1")

            self.assertEqual(3, mock_sock.sendto.call_count)


if __name__ == "__main__":
    unittest.main()