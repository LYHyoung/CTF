#!/usr/bin/env python3
# scan_uds_sessions.py
import time
import can

BUS = 'can0'         # 수정 필요 시 바꿀 것
REQ_ID = 0x7A0       # target request ID
TIMEOUT = 0.25       # 각 전송당 기다릴 시간 (초)
DELAY = 0.01         # 전송 간 짧은 지연

def send_sf(bus, req_id, subfn):
    # ISO-TP single frame: PCI byte = length (2) -> 0x02, then 0x10, subfn, pad zeros
    data = [0x02, 0x10, subfn, 0x00,0x00,0x00,0x00,0x00]
    msg = can.Message(arbitration_id=req_id, data=bytes(data), is_extended_id=False)
    bus.send(msg)

def check_response_for_sub(response, subfn):
    # response.data: [PCI, svc_or_0x7F, ...]
    # Positive: 0x50 at index 1 and subfn at index 2 for SF responses
    d = bytes(response.data)
    if len(d) >= 3 and d[1] == 0x50 and d[2] == subfn:
        return 'POS'
    # Negative response: 0x7F (service) at index1, 0x10 at index2, NRC at index3
    if len(d) >= 4 and d[1] == 0x7F and d[2] == 0x10:
        return 'NEG'
    # Some devices may use different offsets for multi-frame; we only treat clear POS here
    return None

def main():
    bus = can.interface.Bus(channel=BUS, bustype='socketcan')
    supported = []
    print(f"[+] Scanning 0x00..0xFF on req id 0x{REQ_ID:03X} (interface {BUS})")
    for sub in range(0x00, 0x100):
        send_sf(bus, REQ_ID, sub)
        t0 = time.time()
        got = None
        # listen for TIMEOUT seconds for any response frames
        while time.time() - t0 < TIMEOUT:
            rx = bus.recv(timeout=TIMEOUT)
            if rx is None:
                break
            res = check_response_for_sub(rx, sub)
            if res == 'POS':
                supported.append(sub)
                # consume possible extra frames then break
                break
            elif res == 'NEG':
                # negative -> not supported, stop waiting for this subfn
                break
            # otherwise ignore and keep waiting until timeout
        time.sleep(DELAY)
    bus.shutdown()

    supported.sort()
    if not supported:
        print("[!] No positive responses detected.")
        return

    # format: two-digit hex, lowercase, ascending, comma-separated, no spaces
    flag = ",".join(f"{x:02x}" for x in supported)
    print("FLAG:", flag)

if __name__ == "__main__":
    main()
