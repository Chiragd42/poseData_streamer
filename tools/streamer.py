#!/usr/bin/env python3



##this is chirag dabhere 
"""
XSens UDP streamer (replay) from CSV/tuple logs.

Expected input format per line:
    (b'MXTP02', 732700, 128, 23, 64285324, 0, 0, 0, 0, 0, 0, 2, 224, 1, 0.27, -0.69, ...)
s
The script finds the segment block by locating the sequence of segment IDs
1..23 at stride 8, then packs each segment as:
    int32 segment_id (big-endian)
    7 x float32 (px, py, pz, qw, qx, qy, qz) (big-endian)

It builds a 760-byte MXTP packet:
    6 bytes: b"MXTP02"
    18 bytes: zero padding (header fields ignored by your C++ parser)
    23 segments * 32 bytes
"""

import argparse
import ast
import csv
import signal
import socket
import struct
import time
from typing import Iterable, List, Optional


SIGNATURE = b"MXTP02"
HEADER_SIZE = 24
SEGMENT_COUNT = 23
SEGMENT_STRIDE = 8  # id + 7 floats


def find_segment_start(values: List[float]) -> int:
    """Find the index where segment IDs 1..23 start at stride 8."""
    for i in range(len(values) - SEGMENT_COUNT * SEGMENT_STRIDE + 1):
        ok = True
        for seg_id in range(1, SEGMENT_COUNT + 1):
            idx = i + (seg_id - 1) * SEGMENT_STRIDE
            if int(values[idx]) != seg_id:
                ok = False
                break
        if ok:
            return i
    raise ValueError("Could not locate segment block (IDs 1..23) in row")


def build_packet(values: List[float]) -> bytes:
    """Build a raw MXTP packet from a row of values."""
    seg_start = find_segment_start(values)
    packet = bytearray()
    packet.extend(SIGNATURE)
    packet.extend(b"\x00" * (HEADER_SIZE - len(SIGNATURE)))

    for seg_index in range(SEGMENT_COUNT):
        base = seg_start + seg_index * SEGMENT_STRIDE
        seg_id = int(values[base])
        px, py, pz = float(values[base + 1]), float(values[base + 2]), float(values[base + 3])
        qw, qx, qy, qz = (
            float(values[base + 4]),
            float(values[base + 5]),
            float(values[base + 6]),
            float(values[base + 7]),
        )
        packet.extend(struct.pack(">i7f", seg_id, px, py, pz, qw, qx, qy, qz))

    return bytes(packet)


def _strip_signature(values: List[float]) -> List[float]:
    if values and values[0] == SIGNATURE.decode("utf-8"):
        return values[1:]
    if values and isinstance(values[0], bytes) and values[0] == SIGNATURE:
        return values[1:]
    return values


def _parse_tuple_line(line: str) -> List[float]:
    row = ast.literal_eval(line)
    if not isinstance(row, (list, tuple)):
        return []
    row_list = list(row)
    row_list = _strip_signature(row_list)
    return [float(x) for x in row_list]


def _parse_csv_line(line: str) -> List[float]:
    reader = csv.reader([line], skipinitialspace=True)
    row = next(reader, [])
    if not row:
        return []
    if row[0] in ("MXTP02", "b'MXTP02'", 'b"MXTP02"'):
        row = row[1:]
    return [float(x) for x in row]


def parse_line(line: str) -> List[float]:
    """Parse a line that might be tuple-style or CSV into numeric values."""
    line = line.strip()
    if not line:
        return []
    if line.startswith(("(", "[")):
        return _parse_tuple_line(line)
    return _parse_csv_line(line)


def stream(csv_path: str, ip: str, port: int, rate: float, log_every: int, debug_every: int) -> None:
    interval = 1.0 / rate
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    stop_requested = {"value": False}
    window_sent = 0
    window_start = time.perf_counter()
    next_send_time = time.perf_counter()

    def handle_signal(signum, frame):
        stop_requested["value"] = True
        print("\nStop requested. Finishing current iteration...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while True:
            with open(csv_path, "r", encoding="utf-8") as f:
                for line in f:
                    if stop_requested["value"]:
                        raise KeyboardInterrupt
                    values = parse_line(line)
                    if not values:
                        continue
                    packet = build_packet(values)
                    sock.sendto(packet, (ip, port))
                    sent += 1
                    window_sent += 1

                    now = time.perf_counter()
                    window_dt = now - window_start
                    if window_dt >= 1.0:
                        effective_hz = window_sent / window_dt if window_dt > 0 else 0.0
                        print(f"Effective send rate: {effective_hz:.2f} Hz (target: {rate:.2f} Hz)")
                        window_start = now
                        window_sent = 0

                    if log_every > 0 and sent % log_every == 0:
                        print(f"Sent {sent} packets to {ip}:{port} at {rate} Hz")
                    if debug_every > 0 and sent % debug_every == 0:
                        try:
                            seg_start = find_segment_start(values)
                        except ValueError:
                            seg_start = -1
                        print(
                            f"Debug: sent={sent} values={len(values)} seg_start={seg_start} "
                            f"packet_bytes={len(packet)} signature={packet[:6]}"
                        )

                    next_send_time += interval
                    sleep_for = next_send_time - time.perf_counter()
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                    else:
                        # If we're late, recover by resetting schedule from "now"
                        next_send_time = time.perf_counter()
    except KeyboardInterrupt:
        print(f"\nStopped by user. Total packets sent: {sent}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay XSens UDP packets from CSV logs.")
    parser.add_argument("--csv", required=True, help="Path to CSV/tuple log file")
    parser.add_argument("--ip", default="127.0.0.1", help="Target IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9763, help="Target UDP port (default: 9763)")
    parser.add_argument("--rate", type=float, default=250.0, help="Send rate in Hz (default: 250)")
    parser.add_argument(
        "--log-every",
        type=int,
        default=1000,
        help="Print status every N packets (default: 1000; 0 disables)",
    )
    parser.add_argument(
        "--debug-every",
        type=int,
        default=0,
        help="Print parsing/packet debug info every N packets (default: 0 disables)",
    )
    args = parser.parse_args()

    stream(args.csv, args.ip, args.port, args.rate, args.log_every, args.debug_every)


if __name__ == "__main__":
    main()