#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doip_logical_address_finder.py
No-arg script: listens UDP port 13400 for DoIP Vehicle Announcement/Identification,
extracts VIN (bytes 0-16 of payload) and Logical Address (bytes 17-18), prints logical
address in format 0xabcd and exits.
Run as: sudo python3 doip_logical_address_finder.py
"""

import socket
import re
import sys

DOIP_PORT = 13400
DOIP_HEADER_LEN = 8
VIN_LEN = 17
MIN_PAYLOAD_FOR_LOGICAL = VIN_LEN + 2  # need at least 19 bytes

VIN_RE = re.compile(rb'^[A-HJ-NPR-Z0-9]{17}$')  # basic VIN charset (no I/O/Q)

def pretty_logical(addr_int: int) -> str:
    return f"0x{addr_int:04x}"

def parse_doip_packet(packet: bytes):
    # packet = full UDP payload (including DoIP header)
    if len(packet) <= DOIP_HEADER_LEN:
        return None, None
    payload = packet[DOIP_HEADER_LEN:]
    if len(payload) < MIN_PAYLOAD_FOR_LOGICAL:
        return None, None
    vin_bytes = payload[0:VIN_LEN]
    logical_bytes = payload[VIN_LEN:VIN_LEN+2]
    try:
        vin = vin_bytes.decode('ascii', errors='ignore')
    except:
        vin = None
    if not vin or not VIN_RE.match(vin_bytes):
        # VIN may not be present in all discovery payloads; still try logical address if plausible
        vin = None
    logical = int.from_bytes(logical_bytes, 'big')
    return vin, logical

def main():
    print("[*] DoIP Logical Address Finder")
    print(f"[*] Listening UDP port {DOIP_PORT} (bind all interfaces). Use sudo if needed.\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', DOIP_PORT))
    except PermissionError:
        print("[-] Permission denied binding to port 13400. Try running with sudo.")
        sys.exit(1)
    except Exception as e:
        print("[-] Bind failed:", e)
        sys.exit(1)

    try:
        while True:
            data, addr = s.recvfrom(4096)
            print(f"[>] Packet from {addr}, {len(data)} bytes")
            vin, logical = parse_doip_packet(data)
            if vin:
                print(f"[OK] VIN: {vin}")
            if logical is not None:
                print(f"[OK] Logical Address (raw): {logical}  -> Submit as: {pretty_logical(logical)}")
                # If you only need to submit logical address, print it and exit
                print("\nFLAG:", pretty_logical(logical))
                break
            else:
                print("[*] Payload received but no logical address found (payload too short or malformed).")
    finally:
        s.close()

if __name__ == "__main__":
    main()
