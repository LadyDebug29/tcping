import struct
import time
import click
import socket
from statistic_helper import StatisticHelper
from packets_creator import PacketsCreator
import random


def get_statistics(sh):
    loss = int(100 - round(sh.successed / sh.number_packets_sent, 2) * 100)
    print(
        f"{sh.number_packets_sent} packets transmitted,"
        f" {sh.successed} received, {loss}% packet loss"
    )


def get_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def tcping(ip_target_host, sh, timeout):
    with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
    ) as sock:
        sock.settimeout(timeout)
        packet = PacketsCreator.create_tcp_packet(
            get_ip(), ip_target_host,
            0,
            2
        )
        try:
            sock.sendto(packet, (ip_target_host, 80))
            start_time = time.time()
            while True:
                response = sock.recvfrom(16384)
                if response:
                    end_time = time.time()
                    response_time = end_time - start_time
                    print(
                        f"Connected to {ip_target_host}:"
                        f" time={response_time * 1000}"
                    )
                    sh.successed += 1
                    break
            time.sleep(1)
        except socket.timeout:
            print(f"No response from {ip_target_host}: timeout!")
        finally:
            sh.number_packets_sent += 1


def port_knocking(ports, ip_target_host, seq, timeout):
    with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
    ) as sock:
        sock.settimeout(timeout)
        packet = PacketsCreator.create_tcp_packet(
            get_ip(), ip_target_host,
            seq
        )
        for port in ports:
            try:
                sock.sendto(packet, (ip_target_host, port))
                sock.recvfrom(16384)
                time.sleep(1)
            except socket.timeout:
                print(
                    "Failed to connect to the port."
                    "Incorrect connection sequence"
                )
                return False
            except KeyboardInterrupt:
                print("premature breakup")
                return False
        return True


def establish_connection(ip_target_host, port, timeout):
    with (socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
    ) as sock):
        sock.settimeout(timeout)
        try:
            number_seq_for_establish_connection = random.randint(0, 2966784)
            syn_packet = PacketsCreator.create_tcp_packet(
                get_ip(),
                ip_target_host,
                number_seq_for_establish_connection,
                2
            )
            sock.sendto(syn_packet, (ip_target_host, port))
            data, addr = sock.recvfrom(16384)
            tcp_packet = struct.unpack("!HHIIBBHHH", data[20:40])
            target_seq, ack_flag = tcp_packet[3], tcp_packet[5]
            if target_seq == number_seq_for_establish_connection + 1 \
                    and ack_flag == 18:
                sock.sendto(
                    PacketsCreator.create_tcp_packet(
                        get_ip(),
                        ip_target_host,
                        target_seq + 1,
                        4
                    ),
                    (ip_target_host, port),
                )
                return True
            return False
        except socket.timeout:
            print(f"No response from {ip_target_host}: timeout!")
            return False


@click.command()
@click.option("--c", default=-1)
@click.option("--ports-for-port-knocking", default=None)
@click.argument("ip-target-host")
@click.option("--timeout", default=2)
def main(c, ip_target_host, ports_for_port_knocking, timeout):
    sh = StatisticHelper()
    ports_for_port_knocking = (
        map(int, ports_for_port_knocking.split(","))
        if ports_for_port_knocking is not None
        else []
    )

    if establish_connection(ip_target_host, 80, timeout):
        port_knocking(ports_for_port_knocking, ip_target_host, 0, timeout)
        try:
            while c:
                tcping(ip_target_host, sh, timeout)
                c -= 1
        except KeyboardInterrupt:
            pass
        finally:
            get_statistics(sh)
    else:
        print("the connection has not been established")


if __name__ == "__main__":
    main()
