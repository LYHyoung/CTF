#!/usr/bin/env python3
import time
import can

REQ_ID = 0x7A0
IFACE = "can0"
TIMEOUT = 0.08
GAP = 0.003

def make_sf(payload_bytes):
    if len(payload_bytes) > 7:
        raise ValueError("SF payload max 7 bytes")
    data = bytearray(8)
    data[0] = len(payload_bytes) & 0x0F
    data[1:1+len(payload_bytes)] = bytes(payload_bytes)
    return data

def send_sid(bus, sid):
    data = make_sf([sid])
    msg = can.Message(arbitration_id=REQ_ID, data=data, is_extended_id=False)
    bus.send(msg)
    return msg

def parse_isotp(frame_data, sid):
    if len(frame_data) < 3:
        return None
    pci = frame_data[0] & 0xF0
    idx = 1 if pci == 0x00 else 2 if pci == 0x10 else None
    if idx is None or idx >= len(frame_data):
        return None
    first_payload = frame_data[idx]

    # Positive response
    if first_payload == (sid | 0x40):
        return ("positive", frame_data, None)
    # Negative response
    if first_payload == 0x7F and idx + 2 < len(frame_data):
        req_sid = frame_data[idx + 1]
        nrc = frame_data[idx + 2]
        if req_sid == sid:
            return ("negative", frame_data, nrc)
    return None

def scan_sids():
    supported = []
    with can.interface.Bus(channel=IFACE, bustype="socketcan") as bus:
        for sid in range(0x00, 0x100):
            if sid in (0x3F, 0x7F):
                continue
            if sid == 0x7F:
                continue  # 0x7F는 요청 서비스가 아님
            req_msg = send_sid(bus, sid)
            deadline = time.time() + TIMEOUT
            result = None

            while time.time() < deadline:
                rx = bus.recv(timeout=deadline - time.time())
                if rx is None:
                    break
                result = parse_isotp(rx.data, sid)
                if result:
                    break

            if not result:
                continue

            verdict, response_data, nrc = result

            # 출력 조건: positive or negative but not NRC=0x11
            if verdict == "positive" or (verdict == "negative" and nrc != 0x11):
                supported.append(sid)
                print(f"[+] SID 0x{sid:02X}")
                print(f"    Request : {req_msg.data.hex(' ')}")
                print(f"    Response: {response_data.hex(' ')}\n")

            time.sleep(GAP)
    return supported

if __name__ == "__main__":
    sids = scan_sids()
    print("---- Summary ----")
    print(",".join(f"{sid:02x}" for sid in sorted(sids)))
