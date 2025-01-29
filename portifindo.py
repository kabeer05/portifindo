import sys
import socket
from datetime import datetime
import argparse
import pyfiglet

target = "192.168.1.1"

def printBanner(target):
	logo = pyfiglet.figlet_format("Findo", font="poison")
	print(logo)
	print("-" * 50)
	print("Scanning Target: " + target)
	print("Scanning started at: " + str(datetime.now()))
	print("-" * 50)

def synScan():
	pass

def connectScan():
	pass

def printPorts():
	pass

def main():
	parser = argparse.ArgumentParser(
		prog="Portfindo",
		description="A magical CLI tool to swiftly discover open ports on your network!"
	)

	parser.add_argument("target", metavar="<target>", type=str, help="Target IP address to scan (e.g., 192.168.1.1).")
	args = parser.parse_args();

	target = args.target

	printBanner(target=target)


if __name__ == "__main__":
	main()
