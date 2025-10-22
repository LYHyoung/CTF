#!/usr/bin/env python3
import time
import can

IFACE = "can0"
SCAN_START = 0x700
SCAN_END   = 0x7FF
TIMEOUT = 0.08     # per attempt
GAP = 0.003        # inter-frame gap

def make_sf(payload):
    """ISO-TP Single Frame: [PCI(len), payload..., pad] -> 8B"""
    if len(payload) > 7:
        raise ValueError("SF payload max 7 bytes")
    data = bytearray(8)
    data[0] = len(payload) & 0x0F
    data[1:1+len(payload)] = bytes(payload)
    return data

def send_req(bus, req_id, payload):
    msg = can.Message(arbitration_id=req_id, data=make_sf(payload), is_extended_id=False)
    bus.send(msg)
    return msg

def parse_isotp_for_sid(frame_data, sid):
    """Return True if this frame is ISO-TP SF/FF replying about `sid` (pos or neg)."""
    if len(frame_data) < 3:
        return False
    pci = frame_data[0] & 0xF0
    if pci == 0x00:   # SF
        idx = 1
    elif pci == 0x10: # FF
        idx = 2
        if len(frame_data) < 4:
            return False
    else:
        return False

    first = frame_data[idx]

    # Negative first (충돌 방지: SID|0x40 == 0x7F인 0x3F 대비)
    if first == 0x7F and idx + 2 < len(frame_data):
        req_sid = frame_data[idx+1]
        # nrc = frame_data[idx+2]  # 필요시 활용
        return req_sid == sid

    # Positive (단, 0x7F와 충돌하는 경우 제외)
    if (sid | 0x40) != 0x7F and first == (sid | 0x40):
        return True

    return False

def try_sid(bus, req_id, sid, payload):
    """Send one UDS request, wait response; return (got_response, resp_id, resp_raw)"""
    req_msg = send_req(bus, req_id, payload)
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        rx = bus.recv(timeout=deadline - time.time())
        if rx is None:
            break
        if parse_isotp_for_sid(rx.data, sid):
            # 응답이 어느 ID로 오든, 이 req_id는 ‘요청용’으로 유효
            print(f"[hit] req_id=0x{req_id:03X}  sid=0x{sid:02X}")
            print(f"      request : {req_msg.data.hex(' ')}")
            print(f"      response: {rx.data.hex(' ')}  (resp_id=0x{rx.arbitration_id:03X})\n")
            return True, rx.arbitration_id, rx.data
    time.sleep(GAP)
    return False, None, None

def scan_request_ids():
    hits = []
    with can.interface.Bus(channel=IFACE, bustype="socketcan") as bus:
        for req_id in range(SCAN_START, SCAN_END + 1):
            # 1) TesterPresent (0x3E 0x00)
            ok, _, _ = try_sid(bus, req_id, 0x3E, [0x3E, 0x00])
            if ok:
                hits.append(req_id)
                continue
            # 2) Fallback: DefaultSession (0x10 0x01)
            ok, _, _ = try_sid(bus, req_id, 0x10, [0x10, 0x01])
            if ok:
                hits.append(req_id)
    return sorted(set(hits))

if __name__ == "__main__":
    candidates = scan_request_ids()
    print("---- Candidates (request CAN IDs) ----")
    print(", ".join(f"0x{c:03X}" for c in candidates) if candidates else "(none)")

    # CTF 플래그: 후보가 하나면 3자리 hex만 출력
    if len(candidates) == 1:
        print("\nFLAG:")
        print(f"{candidates[0]:03x}")   # 예: 7a0
