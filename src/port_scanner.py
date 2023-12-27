#!/usr/bin/env python3
"""
Port Scanner in Python

Scans random IPs or specified IP range for open ports. This script
allows users to specify a range of IP addresses and ports to scan for
open TCP connections.

Usage: python port_scanner.py -r <IPRANGE> -p <PORTNUMBERS>
Example: python port_scanner.py -r 192.168.1.1-192.168.1.255 -p 80,443
"""

import socket
import argparse
from ipaddress import ip_network
import random


def scan_port(ip, port):
    """
    Scan a given IP and port.

    Args:
    ip (str): The IP address to scan.
    port (int): The port number to scan.

    Returns:
    bool: True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except (socket.gaierror, OSError):
            return False
        except Exception as e:
            print(e)


def main():
    parser = argparse.ArgumentParser(description='Port Scanner in Python')
    parser.add_argument('-r', '--range', help='IP range to scan')
    parser.add_argument('-p', '--ports', help='Comma-separated port numbers to scan')
    args = parser.parse_args()

    if not args.ports:
        parser.print_help()
        return

    ports = [int(p) for p in args.ports.split(',')]

    if args.range:
        try:
            ip_range = ip_network(args.range)
            ips = [str(ip) for ip in ip_range]
        except ValueError:
            print("Invalid IP range")
            return
    else:
        ips = ["{}.{}.{}.{}".format(random.randint(0, 255), random.randint(0, 255),
                                    random.randint(0, 255), random.randint(0, 255)) for _ in range(256)]

    for ip in ips:
        for port in ports:
            if scan_port(ip, port):
                print(f"IP {ip} has port {port} open.")
            else:
                print(f"IP {ip} has port {port} closed.")


if __name__ == '__main__':
    main()
