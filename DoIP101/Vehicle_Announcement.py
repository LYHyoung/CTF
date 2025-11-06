#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DoIP VIN Finder (no arguments required)
자동으로 UDP DoIP announcement / Vehicle ID request / UDS DID 0xF190 요청을 시도하여
VIN(플래그)을 찾아 출력합니다.
"""

import re
import socket
import time

# ===== 사용자 설정 =====
TARGET_IP   = "192.168.0.10"   # DoIP 서버 IP 주소 (수정 가능)
TARGET_PORT = 13400            # 일반적인 DoIP 포트
INTERFACE   = ""               # 특정 인터페이스 지정 안 하면 전체 수신
SNIFF_TIME  = 4                # UDP announcement 수신 대기 시간 (초)

# ===== 내부 상수 =====
VIN_RE = re.compile(rb'[A-HJ-NPR-Z0-9]{17}')
DOIP_PROTO_VER = 0x02
DOIP_PROTO_VER_INV = (~DOIP_PROTO_VER) & 0xFF
PAYLOAD_VEHICLE_IDENT_REQ = 0x0002
PAYLOAD_DIAGNOSTIC = 0x8001

def build_doip_header(payload_type: int, payload_len: int) -> bytes:
    return bytes([DOIP_PROTO_VER, DOIP_PROTO_VER_INV]) + payload_type.to_bytes(2, 'big') + payload_len.to_bytes(4, 'big')

def find_vin(data: bytes):
    m = VIN_RE.search(data)
    return m.group(0).decode('ascii') if m else None

def sniff_udp_for_vin(timeout=SNIFF_TIME):
    print(f"[+] Listening UDP 13400 for {timeout}s...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', 13400))
    except PermissionError:
        print("[-] root 권한이 필요합니다 (sudo로 실행).")
        return None
    s.settimeout(timeout)
    start = time.time()
    try:
        while time.time() - start < timeout:
            try:
                data, addr = s.recvfrom(2048)
                print(f"[>] UDP packet from {addr} ({len(data)} bytes)")
                vin = find_vin(data)
                if vin:
                    print(f"[OK] VIN found: {vin}")
                    return vin
            except socket.timeout:
                continue
    finally:
        s.close()
    print("[*] No VIN found in UDP announcements.")
    return None

def vehicle_ident_request(host=TARGET_IP, port=TARGET_PORT, timeout=3):
    print(f"[+] Sending DoIP Vehicle ID request to {host}:{port}")
    payload = b''
    header = build_doip_header(PAYLOAD_VEHICLE_IDENT_REQ, len(payload))
    msg = header + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, port))
        try:
            data, _ = s.recvfrom(4096)
            vin = find_vin(data)
            if vin:
                print(f"[OK] VIN found in UDP response: {vin}")
                return vin
        except socket.timeout:
            print("[*] No UDP response.")
    finally:
        s.close()
    return None

def uds_read_f190(host=TARGET_IP, port=TARGET_PORT, timeout=3):
    print(f"[+] Sending DoIP-UDS ReadDataByIdentifier 0x22 F190 ...")
    isotp_sf = bytes([0x03, 0x22, 0xF1, 0x90])
    header = build_doip_header(PAYLOAD_DIAGNOSTIC, len(isotp_sf))
    msg = header + isotp_sf
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        print(f"[-] TCP connect failed: {e}")
        return None
    s.sendall(msg)
    s.settimeout(timeout)
    try:
        resp = s.recv(4096)
        vin = find_vin(resp)
        if vin:
            print(f"[OK] VIN found in UDS response: {vin}")
            return vin
        else:
            print("[*] Response received but VIN not found.")
    except socket.timeout:
        print("[*] No response to UDS request.")
    finally:
        s.close()
    return None

def main():
    print("[*] DoIP VIN Finder starting...\n")

    vin = sniff_udp_for_vin()
    if vin:
        print(f"\nFLAG (VIN): {vin}")
        return

    vin = vehicle_ident_request()
    if vin:
        print(f"\nFLAG (VIN): {vin}")
        return

    vin = uds_read_f190()
    if vin:
        print(f"\nFLAG (VIN): {vin}")
        return

    print("\n[-] VIN not found. Try adjusting TARGET_IP or run tcpdump to inspect traffic.")

if __name__ == "__main__":
    main()
