import sys
import socket
from datetime import datetime
import argparse
import pyfiglet
import re

common_ports = {"tcp": []}

# Result of port scanning
scanned_ports = {
    "open": [],
    "closed": [],
}


def getPortsFromFile():
    global common_ports

    # Common TCP Ports
    tcp_ports = open("lists/common_ports_tcp.txt", "r")
    common_ports["tcp"] = list(map(int, tcp_ports.read().split(",")))


def printBanner(target):
    logo = pyfiglet.figlet_format("Findo", font="poison")
    print(logo)
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at: " + str(datetime.now()))
    print("-" * 50)


def synScanTCP():
    pass


def connectScanTCP(target, ports):
    global scanned_ports
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            result = s.connect_ex((target, port))
            if result == 0:
                scanned_ports["open"].append(port)
            else:
                scanned_ports["closed"].append(port)
            s.close()

    except KeyboardInterrupt:
        print("\n Exiting Program!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved!!!")
        sys.exit()

    printPorts(scanned_ports)


def printPorts(ports):
    print(f"{len(ports["closed"])} closed ports not shown!!!\n")
    print("Port\t\tState")
    for open_port in ports["open"]:
        print(f"{open_port}\t\topen")


def main():
    getPortsFromFile()

    parser = argparse.ArgumentParser(
        prog="Portfindo",
        description="A magical CLI tool to swiftly discover open ports on your network!",
        add_help=False,
    )

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Shows this help message because, clearly, you need it.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        help="Display the version of Portifindo.",
        version="%(prog)s 1.0"
    )
    parser.add_argument(
        "-sS",
        "--scan-stealth",
        action="store_true",
        help="Enable stealth mode to reduce detection by firewalls/IDS.",
    )
    parser.add_argument(
        "-p", "--ports", type=str, help="Port range to scan (e.g., 53 or 22,80,443)."
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Save scan results to a file (e.g., results)."
    )
    parser.add_argument(
        "-P",
        "--protocol",
        type=str,
        choices=["tcp"],
        default="tcp",
        help="Specify the protocol to scan (tcp or udp).",
    )
    parser.add_argument(
        "target",
        metavar="<target>",
        type=str,
        nargs="?",
        help="Target IP address to scan (e.g., 192.168.1.1).",
    )
    args = parser.parse_args()

    target = args.target
    ports = args.ports

    if (
        target == None
        or re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", target) == None
    ):
        print("Invalid IP address. Please enter a valid IP address.")
        sys.exit(1)

    if (ports != None and re.match(r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})(,(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))*$", ports) == None):
        print("Invalid Port/s. Please enter a valid port/s.")
        sys.exit(1)

    scan_ports = list(map(int, ports.split(","))) if ports != None else common_ports["tcp"] # Ports to Scan

    printBanner(target=target)

    if args.scan_stealth == True:
        synScanTCP()
    else:
        connectScanTCP(target=target, ports=scan_ports)


if __name__ == "__main__":
    main()
