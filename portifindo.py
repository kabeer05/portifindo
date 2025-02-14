import sys
import socket
from datetime import datetime
import argparse
import pyfiglet
import re
from scapy.all import *
from scapy.layers.inet import IP, TCP

common_ports = {"tcp": []}

DEFAULT_TIMEOUT = 1


class PortStatus:
    OPEN = "open"
    CLOSED = "closed"


# Result of port scanning
scanned_ports = {
    PortStatus.OPEN: [],
    PortStatus.CLOSED: [],
}


def getPortsFromFile():
    global common_ports

    # Common TCP Ports
    tcp_ports = open("lists/common_ports_tcp.txt", "r")
    common_ports["tcp"] = list(map(int, tcp_ports.read().split(",")))


def printBanner(target):
    logo = pyfiglet.figlet_format("Findo", font="poison")
    formatted_time = datetime.now().strftime("%B %d, %Y at %I:%M:%S %p")

    print(logo)
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at: " + formatted_time)
    print("-" * 50)


def getServiceName(port):
    """Returns the service name for a given port (< 1024)."""

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def bannerGrabbing(target, port):
    """Perform banner grabbing to identify services on open ports."""

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(DEFAULT_TIMEOUT)
        s.connect((target, port))
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        server_info = [
            line for line in banner.split("\r\n") if line.lower().startswith("server:")
        ]
        return server_info[0].split(": ")[1] if server_info else "Unknown"
    except:
        return None
    finally:
        s.close()


def detectService(target, port):
    """
    Perform service detection using:
    1. getservbyport for well-known services
    2. Banner grabbing for custom or unknown services
    """

    service_name = getServiceName(port)
    if service_name == None:
        service_name = bannerGrabbing(target, port)
    return service_name


def synScanTCP(target, ports):
    """Performs a TCP SYN/RST scan on the target IP address."""

    global scanned_ports
    try:
        for port in ports:
            syn_pkt = sr1(
                IP(dst=target) / TCP(dport=port, flags="S"),
                timeout=DEFAULT_TIMEOUT,
                verbose=0,
            )

            if (syn_pkt is not None) and (syn_pkt.haslayer(TCP)):
                if syn_pkt.getlayer(TCP).flags == 0x12:
                    rst_pkt = sr1(
                        IP(dst=target) / TCP(dport=port, flags="R"),
                        timeout=DEFAULT_TIMEOUT,
                        verbose=0,
                    )
                    service_name = detectService(target, port)
                    scanned_ports[PortStatus.OPEN].append((port, service_name))
                if syn_pkt.getlayer(TCP).flags == 0x14:
                    scanned_ports[PortStatus.CLOSED].append(port)
            else:
                scanned_ports[PortStatus.CLOSED].append(port)
        printScanResults(scanned_ports)

    except KeyboardInterrupt:
        print("\n Exiting Program!!!")
        sys.exit(0)
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved!!!")
        sys.exit(1)


def connectScanTCP(target, ports):
    """Performs a TCP connect scan on the target IP address."""

    global scanned_ports
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            result = s.connect_ex((target, port))
            if result == 0:
                service_name = detectService(target, port)
                scanned_ports[PortStatus.OPEN].append((port, service_name))
            else:
                scanned_ports[PortStatus.CLOSED].append(port)
            s.close()

    except KeyboardInterrupt:
        print("\n Exiting Program!!!")
        sys.exit(0)
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved!!!")
        sys.exit(1)

    printScanResults(scanned_ports)


def printScanResults(ports):
    """Displays the scan results."""
    closed_count = len(ports[PortStatus.CLOSED])
    open_ports = ports[PortStatus.OPEN]
    print(f"{closed_count} closed ports not shown.")
    print("Port\t\tState\t\tService")
    for open_port, service_name in open_ports:
        print(f"{open_port}\t\topen\t\t{service_name}")


def validateIP(ip):
    """Validates the IP address input."""

    ip_pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
    return ip is not None and re.match(ip_pattern, ip) is not None


def validatePorts(ports):
    """Validates the ports input."""

    port_pattern = (
        r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|"
        r"[1-5][0-9]{4}|[1-9][0-9]{0,3})"
        r"(,(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|"
        r"[1-5][0-9]{4}|[1-9][0-9]{0,3}))*$"
    )
    return ports is None or re.match(port_pattern, ports) is not None


def saveScanResults(target, filename):
    """Save the scan results to a file."""

    with open(f"{filename}.txt", "w") as f:
        f.write(
            f"Scan results for {target} at {datetime.now().strftime('%B %d, %Y at %I:%M:%S %p')}\n"
        )
        f.write("Port\tState\tService\n")
        for port, service in scanned_ports[PortStatus.OPEN]:
            f.write(f"{port}\t\topen\t\t{service}\n")


def parseArguments():
    """Parses command line arguments."""

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
        version="%(prog)s 1.0",
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
        "-o",
        "--output",
        type=str,
        help="Save scan results to a txt file (e.g., results).",
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
    return parser.parse_args()


def main():
    getPortsFromFile()
    args = parseArguments()
    target = args.target
    ports = args.ports

    if not validateIP(target):
        print("Invalid IP address. Please enter a valid IP address.")
        sys.exit(1)

    if not validatePorts(ports):
        print("Invalid Port/s. Please enter a valid port/s.")
        sys.exit(1)

    scan_ports = (
        list(map(int, ports.split(","))) if ports != None else common_ports["tcp"]
    )

    printBanner(target=target)

    if args.scan_stealth == True:
        synScanTCP(target=target, ports=scan_ports)
    else:
        connectScanTCP(target=target, ports=scan_ports)

    if args.output != None:
        saveScanResults(target, args.output)


if __name__ == "__main__":
    main()
