#!/usr/bin/env python3
import time, sys, argparse
import can

REQ = bytes([0x22, 0xF1, 0x90])  # UDS ReadDataByIdentifier VIN

def send_sf(bus, tx, payload):
    if len(payload) > 7: raise ValueError("payload too long for SF")
    data = bytes([len(payload) & 0x0F]) + payload
    data = data.ljust(8, b'\x00')
    bus.send(can.Message(arbitration_id=tx, data=data, is_extended_id=False))

def send_fc_cts(bus, tx, bs=0, stmin=0):
    # FC(CTS)=0x30, 보내는 곳은 항상 테스터->ECU (요청에 사용한 tx로 보냄)
    data = bytes([0x30, bs & 0xFF, stmin & 0xFF]) + b'\x00'*5
    bus.send(can.Message(arbitration_id=tx, data=data, is_extended_id=False))

def recv_isotp_any_rx(bus, rx_min=0x700, rx_max=0x7FF, tx_for_fc=None, timeout=0.5):
    t0 = time.time()
    assembled = bytearray()
    expected = None
    rx_id = None
    while True:
        if time.time() - t0 > timeout: return None, None
        msg = bus.recv(0.01)
        if not msg: continue
        if not (rx_min <= msg.arbitration_id <= rx_max): continue
        data = bytes(msg.data)
        if not data: continue
        pci_type = (data[0] & 0xF0) >> 4
        if pci_type == 0x0:  # SF
            L = data[0] & 0x0F
            return msg.arbitration_id, data[1:1+L]
        if pci_type == 0x1:  # FF
            rx_id = msg.arbitration_id
            expected = ((data[0] & 0x0F) << 8) | data[1]
            assembled.extend(data[2:])
            if tx_for_fc is not None:
                send_fc_cts(bus, tx_for_fc, bs=0, stmin=0)
            # 이어서 CF 수집
            while True:
                if time.time() - t0 > timeout: return rx_id, bytes(assembled) if assembled else None
                m2 = bus.recv(0.1)
                if not m2 or m2.arbitration_id != rx_id: continue
                d2 = bytes(m2.data)
                if ((d2[0] & 0xF0) >> 4) != 0x2: continue  # CF만
                assembled.extend(d2[1:])
                if expected is not None and len(assembled) >= expected:
                    return rx_id, bytes(assembled[:expected])

def parse_vin(payload):
    # UDS positive: 62 F1 90 <VIN...>
    if payload and payload[0] == 0x62 and len(payload) >= 3:
        vin_bytes = payload[3:]
        try: return vin_bytes.decode('ascii', 'ignore').strip('\x00')
        except: return None
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--channel', default='can0')
    ap.add_argument('--tx-start', type=lambda x:int(x,0), default=0x700)
    ap.add_argument('--tx-end',   type=lambda x:int(x,0), default=0x7FF)
    ap.add_argument('--timeout', type=float, default=0.5, help='per-TX receive window')
    ap.add_argument('--retries', type=int, default=2)
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    bus = can.interface.Bus(channel=args.channel, bustype='socketcan')
    print(f"[+] Probing TX 0x{args.tx_start:X}..0x{args.tx_end:X} with UDS 22 F1 90")

    for tx in range(args.tx_start, args.tx_end+1):
        for k in range(args.retries):
            try:
                send_sf(bus, tx, REQ)
            except Exception as e:
                if args.verbose: print(f"tx=0x{tx:X} send err: {e}")
                continue
            rx, payload = recv_isotp_any_rx(
                bus, rx_min=0x700, rx_max=0x7FF, tx_for_fc=tx, timeout=args.timeout
            )
            if payload:
                if args.verbose:
                    print(f"[=] tx=0x{tx:X} <- rx=0x{rx:X} payload={payload.hex()}")
                vin = parse_vin(payload)
                if vin and len(vin) >= 10:  # VIN은 보통 17자
                    print(f"[★] VIN (flag) = {vin}  (tx=0x{tx:X}, rx=0x{rx:X})")
                    return
                else:
                    # 다른 DID거나 포맷일 수 있으니 참고 출력
                    if args.verbose:
                        print(f"    (+) unparsed payload: {payload.hex()}")
            # 작은 딜레이로 버스 과부하 방지
            time.sleep(0.003)

    print("[-] Not found. Try increasing --timeout/--retries or verify the ID window.")

if __name__ == '__main__':
    main()
