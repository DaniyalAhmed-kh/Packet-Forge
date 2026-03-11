"""
PacketForge Fuzzer – Campaign engine with smart mutations, rate control,
anomaly detection, and live statistics.
"""
from __future__ import annotations

import copy
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from packetforge.engine import (
    FieldInfo, PacketStack, default_iface, get_layer_fields, set_layer_field,
)
from packetforge.mutations import Mutation, ALL_MUTATIONS, MUTATION_REGISTRY


# ── Campaign config ────────────────────────────────────────────────────────────
@dataclass
class FuzzConfig:
    iface: str = ""
    target_ip: str = ""
    target_port: int = 0
    pps: float = 100.0           # packets per second (0 = unlimited)
    max_packets: int = 1000
    timeout: float = 2.0
    mutations: List[str] = field(default_factory=lambda: [
        "boundary", "bit_flip", "proto_specific"
    ])
    fuzz_layers: List[str] = field(default_factory=list)  # empty = all
    fuzz_fields: List[str] = field(default_factory=list)  # empty = all
    stop_on_response: bool = False
    capture_responses: bool = True
    seed: Optional[int] = None
    verbose: bool = False

    @property
    def delay(self) -> float:
        return (1.0 / self.pps) if self.pps > 0 else 0.0


# ── Per-packet result ─────────────────────────────────────────────────────────
class ResultType(Enum):
    SENT      = auto()
    RESPONSE  = auto()
    TIMEOUT   = auto()
    ERROR     = auto()
    ANOMALY   = auto()


@dataclass
class FuzzResult:
    seq: int
    result_type: ResultType
    mutation_desc: str
    layer: str
    field_name: str
    mutated_value: Any
    response_summary: str = ""
    rtt_ms: float = 0.0
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def is_interesting(self) -> bool:
        return self.result_type in (ResultType.RESPONSE, ResultType.ANOMALY)


# ── Campaign statistics ────────────────────────────────────────────────────────
@dataclass
class CampaignStats:
    total_sent: int = 0
    total_responses: int = 0
    total_errors: int = 0
    total_anomalies: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    # Field-level coverage
    fields_mutated: Set[str] = field(default_factory=set)
    mutations_applied: Dict[str, int] = field(default_factory=dict)

    # Response code distribution
    response_codes: Dict[str, int] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def pps_actual(self) -> float:
        e = self.elapsed
        return self.total_sent / e if e > 0 else 0.0

    @property
    def response_rate(self) -> float:
        return (self.total_responses / self.total_sent * 100) if self.total_sent else 0.0

    def record(self, result: FuzzResult) -> None:
        if result.result_type == ResultType.SENT:
            self.total_sent += 1
            self.fields_mutated.add(f"{result.layer}.{result.field_name}")
            self.mutations_applied[result.mutation_desc] = \
                self.mutations_applied.get(result.mutation_desc, 0) + 1
        elif result.result_type == ResultType.RESPONSE:
            self.total_sent += 1
            self.total_responses += 1
        elif result.result_type == ResultType.TIMEOUT:
            self.total_sent += 1
        elif result.result_type == ResultType.ERROR:
            self.total_sent += 1
            self.total_errors += 1
        elif result.result_type == ResultType.ANOMALY:
            self.total_anomalies += 1


# ── Mutation iterator ─────────────────────────────────────────────────────────
def _mutation_iterator(
    stack: PacketStack,
    config: FuzzConfig,
) -> Iterator[Tuple[PacketStack, str, str, str, Any]]:
    """
    Yields (mutated_stack, layer_name, field_name, mutation_name, new_value)
    for every applicable mutation of every requested field.
    """
    mutations = [MUTATION_REGISTRY[n] for n in config.mutations
                 if n in MUTATION_REGISTRY]
    if not mutations:
        mutations = ALL_MUTATIONS

    for layer_idx, layer in enumerate(stack.layers):
        lname = type(layer).__name__
        if config.fuzz_layers and lname not in config.fuzz_layers:
            continue

        fields = get_layer_fields(layer)
        for fi in fields:
            if config.fuzz_fields and fi.name not in config.fuzz_fields:
                continue

            for mut in mutations:
                if not mut.applies_to(fi):
                    continue
                for new_val in mut.generate(fi):
                    mutated = stack.clone()
                    ml = mutated.layers[layer_idx]
                    ok, _ = set_layer_field(ml, fi.name, str(new_val)
                                            if not isinstance(new_val, bytes)
                                            else new_val.hex())
                    if ok:
                        yield mutated, lname, fi.name, mut.name, new_val


# ── Anomaly detector ──────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Heuristics for detecting interesting crash/anomaly responses.
    Compares against a baseline response to flag deviations.
    """
    def __init__(self):
        self.baseline_size: Optional[int] = None
        self.baseline_flags: Optional[int] = None
        self.crash_indicators: Set[str] = {"RST", "ICMP", "unreachable"}

    def set_baseline(self, response_bytes: int, flags: int = 0) -> None:
        self.baseline_size = response_bytes
        self.baseline_flags = flags

    def is_anomaly(self, response: Any) -> Tuple[bool, str]:
        if response is None:
            return False, ""
        try:
            # Import lazily to avoid hard dep
            from scapy.layers.inet import TCP, ICMP, IP
            resp_bytes = len(bytes(response))

            # ICMP error responses are interesting
            if response.haslayer(ICMP):
                icmp = response[ICMP]
                if icmp.type in (3, 4, 5, 11, 12):
                    return True, f"ICMP type={icmp.type} (error/redirect)"

            # TCP RST when not expected
            if response.haslayer(TCP):
                flags = response[TCP].flags
                if flags & 0x04:  # RST set
                    return True, f"TCP RST received (flags=0x{flags:02x})"

            # Size deviation from baseline
            if self.baseline_size is not None:
                deviation = abs(resp_bytes - self.baseline_size)
                if deviation > self.baseline_size * 0.5 and deviation > 20:
                    return True, (
                        f"Response size deviation: {resp_bytes}B vs "
                        f"baseline {self.baseline_size}B"
                    )
        except Exception:
            pass
        return False, ""


# ── Fuzzing campaign ──────────────────────────────────────────────────────────
class FuzzCampaign:
    """
    Manages a complete fuzzing campaign:
    – iterates mutations
    – sends packets at configured rate
    – captures responses
    – detects anomalies
    – emits results via callback or queue
    """

    def __init__(
        self,
        template: PacketStack,
        config: FuzzConfig,
        on_result: Optional[Callable[[FuzzResult], None]] = None,
    ):
        self.template  = template
        self.config    = config
        self.on_result = on_result
        self.stats     = CampaignStats()
        self.detector  = AnomalyDetector()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.results: List[FuzzResult] = []

    # ── Control ───────────────────────────────────────────────────────────────
    def start(self, blocking: bool = False) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if blocking:
            self._thread.join()

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Main loop ─────────────────────────────────────────────────────────────
    def _run(self) -> None:
        self.stats.start_time = time.time()
        seq = 0
        iface = self.config.iface or default_iface()

        for mutated, lname, fname, mname, mval in _mutation_iterator(
            self.template, self.config
        ):
            if self._stop_event.is_set():
                break
            if seq >= self.config.max_packets:
                break

            t_start = time.time()
            result: FuzzResult

            if self.config.capture_responses:
                resp, msg = mutated.send_recv(
                    iface=iface, timeout=self.config.timeout,
                    verbose=self.config.verbose,
                )
                rtt = (time.time() - t_start) * 1000

                is_anom, anom_msg = self.detector.is_anomaly(resp)

                if resp is not None:
                    result = FuzzResult(
                        seq=seq,
                        result_type=ResultType.ANOMALY if is_anom else ResultType.RESPONSE,
                        mutation_desc=mname,
                        layer=lname,
                        field_name=fname,
                        mutated_value=mval,
                        response_summary=anom_msg or str(resp.summary()),
                        rtt_ms=rtt,
                    )
                else:
                    result = FuzzResult(
                        seq=seq,
                        result_type=ResultType.TIMEOUT,
                        mutation_desc=mname,
                        layer=lname,
                        field_name=fname,
                        mutated_value=mval,
                        rtt_ms=rtt,
                    )
            else:
                ok, err = mutated.send_packet(
                    iface=iface, count=1, verbose=self.config.verbose
                )
                result = FuzzResult(
                    seq=seq,
                    result_type=ResultType.SENT if ok else ResultType.ERROR,
                    mutation_desc=mname,
                    layer=lname,
                    field_name=fname,
                    mutated_value=mval,
                    error=err,
                )

            self.stats.record(result)
            self.results.append(result)
            if self.on_result:
                self.on_result(result)

            seq += 1

            # Rate limiting
            if self.config.delay > 0:
                elapsed = time.time() - t_start
                sleep = self.config.delay - elapsed
                if sleep > 0:
                    time.sleep(sleep)

        self.stats.end_time = time.time()

    # ── Reporting ─────────────────────────────────────────────────────────────
    def interesting_results(self) -> List[FuzzResult]:
        return [r for r in self.results if r.is_interesting]

    def summary(self) -> Dict[str, Any]:
        s = self.stats
        return {
            "total_sent":      s.total_sent,
            "total_responses": s.total_responses,
            "total_errors":    s.total_errors,
            "total_anomalies": s.total_anomalies,
            "elapsed_s":       round(s.elapsed, 2),
            "pps_actual":      round(s.pps_actual, 1),
            "response_rate":   round(s.response_rate, 1),
            "fields_mutated":  len(s.fields_mutated),
            "mutations_used":  list(s.mutations_applied.keys()),
        }
