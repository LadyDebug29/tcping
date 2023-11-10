import sys
import time
import click
import socket
import struct
from statistic_helper import StatisticHelper


def get_statistics(sh):
    loss = int(100 - round(sh.successed / sh.number_packets_sent, 2) * 100)
    print(f"{sh.number_packets_sent} packets transmitted, {sh.successed} received, {loss}% packet loss")


def tcping(host, sh):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.settimeout(1)
        try:
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                69, 0, 40, 54321, 0, 64, 6, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton(host)
            )
            tcp_header = struct.pack("!HHIIBBHHH",
                                     12345, 80, 54321, 0, 5 << 4, 2 << 1, 0, 0, 0)
            packet = ip_header + tcp_header
            sock.sendto(packet, (host, 80))
            start_time = time.time()
            while True:
                response = sock.recv(4096)
                if response:
                    end_time = time.time()
                    response_time = end_time - start_time
                    print(f"Connected to {host}: time={response_time * 1000}")
                    sh.successed += 1
                    break
                if sock.timeout:
                    print(f"No response from {host}: timeout!")
                    break
            time.sleep(1)
        except KeyboardInterrupt:
            get_statistics(sh)
            raise KeyboardInterrupt
        finally:
            sh.number_packets_sent += 1


def port_knocking(ports, host):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.settimeout(1)
        for port in ports:
            try:
                ip_header = struct.pack(
                    "!BBHHHBBH4s4s",
                    69, 0, 40, 54321, 0, 64, 6, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton(host)
                )
                tcp_header = struct.pack("!HHIIBBHHH",
                                         port, 80, 54321, 0, 5 << 4, 2 << 1, 0, 0, 0)
                packet = ip_header + tcp_header
                sock.sendto(packet, (host, 0))
                time.sleep(1)
            except KeyboardInterrupt:
                print("Failed to connect to the port. Incorrect connection sequence")
                raise KeyboardInterrupt


@click.command()
@click.option("--c", default=0)
@click.argument("host")
def main(c, host):
    sh = StatisticHelper()
    ports = [49152, 62834, 52142]
    port_knocking(ports, host)
    if not c:
        try:
            while True:
                tcping(host, sh)
        except KeyboardInterrupt:
            sys.exit()
    else:
        for number_packets_sent in range(c):
            tcping(host, sh)
    get_statistics(sh)
    sys.exit()


if __name__ == "__main__":
    main()
