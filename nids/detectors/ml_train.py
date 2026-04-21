"""
nids/detectors/ml_train.py
CLI tool to train the IsolationForest ML model on baseline "known-good" traffic.

Usage:
    python -m nids.detectors.ml_train --pcap capture.pcap --out models/iforest.pkl
    python -m nids.detectors.ml_train --live --duration 600 --iface wlan0 --out models/iforest.pkl
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import List

from nids.core.schemas import PacketEvent
from nids.detectors.ml_engine import extract_features, FEATURE_NAMES


logger = logging.getLogger("nids.detectors.ml_train")


def _pcap_to_packets(pcap_path: str) -> List[PacketEvent]:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP

    events: List[PacketEvent] = []
    for pkt in rdpcap(pcap_path):
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A", 0x20: "U"}
            flags = "".join(v for k, v in flag_map.items() if pkt[TCP].flags & k)
        elif UDP in pkt:
            proto, sport, dport, flags = "UDP", pkt[UDP].sport, pkt[UDP].dport, ""
        elif ICMP in pkt:
            proto, sport, dport, flags = "ICMP", 0, 0, ""
        else:
            proto, sport, dport, flags = "OTHER", 0, 0, ""

        events.append(
            PacketEvent(
                timestamp=float(pkt.time) if hasattr(pkt, "time") else time.time(),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=sport,
                dst_port=dport,
                proto=proto,
                flags=flags,
                size=len(pkt),
                payload_preview=bytes(ip.payload)[:256],
            )
        )
    return events


def _live_capture(iface: str, duration: int, bpf: str) -> List[PacketEvent]:
    from nids.core.capture import ScapyCapture

    events: List[PacketEvent] = []
    capture = ScapyCapture(interface=iface, bpf_filter=bpf, queue_maxsize=20000)
    capture.set_callback(lambda p: events.append(p))
    logger.info(f"Starting live capture on {iface} for {duration}s …")
    capture.start()
    try:
        time.sleep(duration)
    finally:
        capture.stop()
    return events


def train(packets: List[PacketEvent], out_path: str, contamination: float) -> None:
    if len(packets) < 50:
        raise SystemExit(f"Not enough packets to train ({len(packets)}) — need >= 50")

    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib

    X = np.array([extract_features(p) for p in packets], dtype=float)
    logger.info(f"Training IsolationForest on {X.shape[0]} packets, {X.shape[1]} features")

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    joblib.dump(model, out_path)

    meta = {
        "trained_at": time.time(),
        "trained_at_human": time.strftime("%Y-%m-%d %H:%M:%S"),
        "packet_count": int(X.shape[0]),
        "feature_names": FEATURE_NAMES,
        "contamination": contamination,
        "model_version": "iforest-v1",
    }
    with open(out_path + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Saved model to {out_path}")
    logger.info(f"Saved sidecar to {out_path}.meta.json")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Train IsolationForest baseline for NIDS")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Path to a baseline pcap file")
    src.add_argument("--live", action="store_true", help="Capture live traffic")

    parser.add_argument("--duration", type=int, default=600, help="Live capture seconds")
    parser.add_argument("--iface", default="wlan0", help="Live capture interface")
    parser.add_argument("--bpf", default="ip and (tcp or udp or icmp)", help="BPF filter")
    parser.add_argument("--out", default="models/iforest.pkl", help="Output model path")
    parser.add_argument("--contamination", type=float, default=0.01)

    args = parser.parse_args(argv)

    packets = _pcap_to_packets(args.pcap) if args.pcap else _live_capture(args.iface, args.duration, args.bpf)
    logger.info(f"Collected {len(packets)} packets for training")
    train(packets, args.out, args.contamination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
