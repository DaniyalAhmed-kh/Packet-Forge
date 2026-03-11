"""
PacketForge Replay Engine – load PCAP, replay with mutations, timing control.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from packetforge.engine import SCAPY_AVAILABLE, default_iface


@dataclass
class ReplayConfig:
    iface: str = ""
    pps: float = 100.0          # packets/second (0 = original timing)
    loop: int = 1               # number of replay passes
    randomise_src_ip: bool = False
    randomise_src_mac: bool = False
    randomise_src_port: bool = False
    bpf_filter: str = ""        # filter applied when loading pcap
    start_packet: int = 0       # offset into pcap
    max_packets: int = 10_000
    verbose: bool = False

    @property
    def delay(self) -> float:
        return (1.0 / self.pps) if self.pps > 0 else 0.0


@dataclass
class ReplayStats:
    total_packets: int = 0
    sent: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    current_pass: int = 1

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def pps_actual(self) -> float:
        e = self.elapsed
        return self.sent / e if e > 0 else 0.0


@dataclass
class ReplayResult:
    seq: int
    ok: bool
    error: str = ""
    timestamp: float = field(default_factory=time.time)


class ReplayEngine:
    """Load a PCAP and replay its packets, optionally applying mutations."""

    def __init__(
        self,
        pcap_path: str,
        config: Optional[ReplayConfig] = None,
        on_result: Optional[Callable[[ReplayResult], None]] = None,
    ):
        self.pcap_path = pcap_path
        self.config = config or ReplayConfig()
        self.on_result = on_result
        self.stats = ReplayStats()
        self._packets: List[Any] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def load(self) -> Tuple[bool, str]:
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available"
        try:
            from scapy.all import rdpcap, PacketList
            pkts = rdpcap(self.pcap_path)

            if self.config.bpf_filter:
                from scapy.all import conf as scapy_conf
                pkts = PacketList([
                    p for p in pkts
                    if p.sprintf(self.config.bpf_filter, "")
                ])

            start = self.config.start_packet
            end = start + self.config.max_packets
            self._packets = list(pkts)[start:end]
            self.stats.total_packets = len(self._packets)
            return True, f"Loaded {len(self._packets)} packets"
        except Exception as e:
            return False, str(e)

    def start(self, blocking: bool = False) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if blocking:
            self._thread.join()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _mutate(self, pkt: Any) -> Any:
        """Apply configured mutations to a packet."""
        import copy
        import random
        p = pkt.copy()
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.l2 import Ether

            if self.config.randomise_src_ip and p.haslayer(IP):
                p[IP].src = f"{random.randint(1,254)}.{random.randint(0,255)}" \
                            f".{random.randint(0,255)}.{random.randint(1,254)}"
                del p[IP].chksum

            if self.config.randomise_src_mac and p.haslayer(Ether):
                p[Ether].src = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

            if self.config.randomise_src_port:
                if p.haslayer(TCP):
                    p[TCP].sport = random.randint(1024, 65535)
                    del p[TCP].chksum
                elif p.haslayer(UDP):
                    p[UDP].sport = random.randint(1024, 65535)
                    del p[UDP].chksum
        except Exception:
            pass
        return p

    def _run(self) -> None:
        if not SCAPY_AVAILABLE:
            return
        from scapy.all import sendp, send
        from scapy.layers.l2 import Ether

        self.stats.start_time = time.time()
        iface = self.config.iface or default_iface()
        seq = 0

        for pass_num in range(max(1, self.config.loop)):
            if self._stop.is_set():
                break
            self.stats.current_pass = pass_num + 1

            prev_time: Optional[float] = None

            for pkt in self._packets:
                if self._stop.is_set():
                    break

                t_start = time.time()

                # Timing: original vs configured PPS
                if self.config.pps == 0 and prev_time is not None:
                    try:
                        inter = float(pkt.time) - prev_time  # type: ignore[attr-defined]
                        if inter > 0:
                            time.sleep(min(inter, 5.0))
                    except Exception:
                        pass
                prev_time = getattr(pkt, "time", time.time())

                p = self._mutate(pkt)

                try:
                    if p.haslayer(Ether):
                        sendp(p, iface=iface, verbose=self.config.verbose)
                    else:
                        send(p, verbose=self.config.verbose)
                    self.stats.sent += 1
                    result = ReplayResult(seq=seq, ok=True)
                except Exception as e:
                    self.stats.errors += 1
                    result = ReplayResult(seq=seq, ok=False, error=str(e))

                if self.on_result:
                    self.on_result(result)
                seq += 1

                # Rate limiting
                if self.config.pps > 0:
                    elapsed = time.time() - t_start
                    wait = self.config.delay - elapsed
                    if wait > 0:
                        time.sleep(wait)

        self.stats.end_time = time.time()

    def packet_summaries(self) -> List[str]:
        """Return human-readable summary for each loaded packet."""
        summaries = []
        for i, pkt in enumerate(self._packets):
            try:
                summaries.append(f"{i:4d}  {pkt.summary()}")
            except Exception:
                summaries.append(f"{i:4d}  <error>")
        return summaries

    def pcap_info(self) -> Dict[str, Any]:
        """High-level info about the loaded PCAP."""
        from collections import Counter
        if not self._packets:
            return {}
        proto_counts: Counter = Counter()
        for pkt in self._packets:
            try:
                proto_counts[type(pkt).__name__] += 1
            except Exception:
                pass
        return {
            "path": self.pcap_path,
            "packets": len(self._packets),
            "protocols": dict(proto_counts.most_common(10)),
        }

    def summary(self) -> Dict[str, Any]:
        s = self.stats
        return {
            "pcap": self.pcap_path,
            "total_packets": s.total_packets,
            "sent": s.sent,
            "errors": s.errors,
            "passes": self.config.loop,
            "elapsed_s": round(s.elapsed, 2),
            "pps_actual": round(s.pps_actual, 1),
        }
