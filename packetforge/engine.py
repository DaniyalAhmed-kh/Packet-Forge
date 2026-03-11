"""
PacketForge Engine - Core packet crafting, field management, send/receive
"""
from __future__ import annotations

import copy
import io
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Type

# ── Scapy ────────────────────────────────────────────────────────────────────
SCAPY_AVAILABLE = False
try:
    # Disable IPv6 routing init before loading scapy (avoids sandbox errors)
    import scapy.config as _sc; _sc.conf.ipv6_enabled = False  # noqa
    from scapy.layers.l2 import ARP, Dot1Q, Ether, GRE
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Packet, Raw
    from scapy.sendrecv import send, sendp, sr, sr1, srp
    from scapy.utils import rdpcap, wrpcap
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None  # type: ignore[assignment,misc]
    try:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
    except Exception:
        DNS = DNSQR = DNSRR = None  # type: ignore[assignment,misc]
    try:
        from scapy.layers.ntp import NTP
    except Exception:
        NTP = None  # type: ignore[assignment,misc]
    import scapy.all as scapy  # noqa – full namespace for sniff/conf
    from scapy.all import conf, hexdump, ls
    SCAPY_AVAILABLE = True
except Exception:
    pass

# ── Layer registry ────────────────────────────────────────────────────────────
LAYER_REGISTRY: Dict[str, Any] = {}
LAYER_GROUPS: Dict[str, List[str]] = {
    "L2 – Data Link": ["Ether", "ARP", "Dot1Q", "GRE"],
    "L3 – Network":   ["IP", "IPv6", "ICMP"],
    "L4 – Transport": ["TCP", "UDP"],
    "Application":    ["DNS", "DNSQR", "NTP", "Raw"],
}

if SCAPY_AVAILABLE:
    LAYER_REGISTRY = {
        "Ether": Ether, "ARP": ARP, "Dot1Q": Dot1Q, "GRE": GRE,
        "IP": IP, "IPv6": IPv6, "ICMP": ICMP,
        "TCP": TCP, "UDP": UDP,
        "DNS": DNS, "DNSQR": DNSQR, "NTP": NTP,
        "Raw": Raw,
    }


# ── Field metadata ─────────────────────────────────────────────────────────────
@dataclass
class FieldInfo:
    name: str
    value: Any
    default: Any
    ftype: str          # "int", "str", "mac", "ip", "bytes", "enum"
    choices: Optional[Dict[int, str]] = None
    comment: str = ""

    @property
    def display_value(self) -> str:
        if self.ftype == "bytes" and isinstance(self.value, (bytes, bytearray)):
            return self.value.hex()
        if self.ftype == "enum" and self.choices and isinstance(self.value, int):
            label = self.choices.get(self.value, "")
            return f"{self.value} ({label})" if label else str(self.value)
        return str(self.value) if self.value is not None else ""


def _classify_field(fd: Any) -> str:
    """Map a scapy FieldDesc to a simplified type string."""
    name = type(fd).__name__
    if "MAC" in name or "MACField" in name:
        return "mac"
    if "IP" in name and "Field" in name:
        return "ip"
    if "Enum" in name or "Flag" in name:
        return "enum"
    if "Byte" in name or "Short" in name or "Int" in name or "Long" in name or "Signed" in name:
        return "int"
    if "Str" in name or "str" in name.lower():
        return "str"
    if "XBytes" in name or "Raw" in name or "Payload" in name:
        return "bytes"
    return "str"


def get_layer_fields(layer: Any) -> List[FieldInfo]:
    """Extract FieldInfo list from a scapy layer instance."""
    if not SCAPY_AVAILABLE:
        return []
    fields = []
    for fd in layer.fields_desc:
        try:
            val = getattr(layer, fd.name, fd.default)
            default = fd.default
            ftype = _classify_field(fd)
            choices = None
            if hasattr(fd, "enum"):
                choices = {k: v for k, v in fd.enum.items()}
            elif hasattr(fd, "names"):
                choices = {i: n for i, n in enumerate(fd.names) if n}
            fields.append(FieldInfo(
                name=fd.name, value=val, default=default,
                ftype=ftype, choices=choices,
            ))
        except Exception:
            pass
    return fields


def set_layer_field(layer: Any, name: str, raw_value: str) -> Tuple[bool, str]:
    """Parse raw_value string and set it on layer.name. Returns (ok, error)."""
    if not SCAPY_AVAILABLE:
        return False, "Scapy not available"
    try:
        fd_map = {fd.name: fd for fd in layer.fields_desc}
        fd = fd_map.get(name)
        if fd is None:
            return False, f"Unknown field: {name}"

        ftype = _classify_field(fd)
        if ftype in ("int", "enum"):
            # Support hex (0x...) or decimal
            try:
                val = int(raw_value, 16) if raw_value.startswith("0x") else int(raw_value)
            except (ValueError, TypeError):
                val = raw_value  # fall back to string (e.g. TCP flag names)
        elif ftype in ("mac",):
            val = raw_value.strip()
        elif ftype in ("ip",):
            val = raw_value.strip()
        elif ftype == "bytes":
            val = bytes.fromhex(raw_value.replace(":", "").replace(" ", ""))
        else:
            val = raw_value
        # Set and immediately test-build to catch Scapy type errors early
        old_val = getattr(layer, name, None)
        setattr(layer, name, val)
        try:
            bytes(layer)  # force a build to validate
        except Exception as e:
            setattr(layer, name, old_val)  # roll back
            return False, f"Invalid value for {name}: {e}"
        return True, ""
    except Exception as e:
        return False, str(e)


# ── PacketStack ───────────────────────────────────────────────────────────────
@dataclass
class PacketStack:
    """Mutable ordered stack of scapy layers representing a packet."""
    layers: List[Any] = field(default_factory=list)
    name: str = "unnamed"

    # ── Layer management ──────────────────────────────────────────────────────
    def add_layer(self, layer_name: str, index: Optional[int] = None) -> Tuple[bool, str]:
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available"
        cls = LAYER_REGISTRY.get(layer_name)
        if cls is None:
            return False, f"Unknown layer: {layer_name}"
        inst = cls()
        if index is None:
            self.layers.append(inst)
        else:
            self.layers.insert(index, inst)
        return True, ""

    def remove_layer(self, index: int) -> Tuple[bool, str]:
        if index < 0 or index >= len(self.layers):
            return False, "Index out of range"
        self.layers.pop(index)
        return True, ""

    def move_layer(self, from_idx: int, to_idx: int) -> None:
        layer = self.layers.pop(from_idx)
        self.layers.insert(to_idx, layer)

    def get_layer(self, index: int) -> Optional[Any]:
        if 0 <= index < len(self.layers):
            return self.layers[index]
        return None

    def layer_names(self) -> List[str]:
        return [type(l).__name__ for l in self.layers]

    # ── Build / send ──────────────────────────────────────────────────────────
    def build(self) -> Optional[Any]:
        if not self.layers:
            return None
        pkt = self.layers[0]
        for l in self.layers[1:]:
            pkt = pkt / l
        return pkt

    def build_bytes(self) -> bytes:
        pkt = self.build()
        if pkt is None:
            return b""
        try:
            return bytes(pkt)
        except Exception:
            return b"<build error>"

    def hex_lines(self, width: int = 16) -> List[str]:
        """Return hex dump as list of formatted strings."""
        raw = self.build_bytes()
        if not raw:
            return ["<empty packet>"]
        lines = []
        for i in range(0, len(raw), width):
            chunk = raw[i:i + width]
            hex_part  = " ".join(f"{b:02x}" for b in chunk)
            asc_part  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}:  {hex_part:<{width*3}}  {asc_part}")
        return lines

    def decode_summary(self) -> List[str]:
        """Human-readable layer summary."""
        pkt = self.build()
        if pkt is None:
            return []
        lines = []
        current = pkt
        while current and current.__class__.__name__ != "NoPayload":
            name = current.__class__.__name__
            try:
                summary = current.summary()
            except Exception:
                summary = name
            lines.append(f"  [{name}] {summary}")
            current = current.payload
        return lines

    def total_bytes(self) -> int:
        return len(self.build_bytes())

    # ── Send / receive ────────────────────────────────────────────────────────
    def send_packet(
        self,
        iface: Optional[str] = None,
        count: int = 1,
        inter: float = 0.0,
        loop: bool = False,
        verbose: bool = False,
    ) -> Tuple[bool, str]:
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available"
        pkt = self.build()
        if pkt is None:
            return False, "Empty packet"
        try:
            # Determine correct send function
            if self.layers and type(self.layers[0]).__name__ == "Ether":
                sendp(pkt, iface=iface, count=count, inter=inter,
                      loop=loop, verbose=verbose)
            else:
                send(pkt, count=count, inter=inter,
                     loop=loop, verbose=verbose)
            return True, f"Sent {count} packet(s)"
        except PermissionError:
            return False, "Permission denied – run as root/sudo"
        except Exception as e:
            return False, str(e)

    def send_recv(
        self,
        iface: Optional[str] = None,
        timeout: float = 2.0,
        verbose: bool = False,
    ) -> Tuple[Optional[Any], str]:
        if not SCAPY_AVAILABLE:
            return None, "Scapy not available"
        pkt = self.build()
        if pkt is None:
            return None, "Empty packet"
        try:
            if self.layers and type(self.layers[0]).__name__ == "Ether":
                ans, _ = srp(pkt, iface=iface, timeout=timeout, verbose=verbose)
            else:
                ans, _ = sr(pkt, timeout=timeout, verbose=verbose)
            if ans:
                return ans[0][1], "Response received"
            return None, "No response"
        except PermissionError:
            return None, "Permission denied – run as root/sudo"
        except Exception as e:
            return None, str(e)

    # ── Serialization ─────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        layers_data = []
        for layer in self.layers:
            lname = type(layer).__name__
            fields: Dict[str, Any] = {}
            for fd in layer.fields_desc:
                try:
                    val = getattr(layer, fd.name)
                    if isinstance(val, bytes):
                        val = {"__bytes__": val.hex()}
                    elif hasattr(val, '__int__') and not isinstance(val, (int, float, str, bool)):
                        val = int(val)  # convert scapy Flag/Enum to plain int
                    fields[fd.name] = val
                except Exception:
                    pass
            layers_data.append({"layer": lname, "fields": fields})
        return {"name": self.name, "layers": layers_data}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketStack":
        ps = cls(name=data.get("name", "unnamed"))
        for ldata in data.get("layers", []):
            lname = ldata["layer"]
            lcls = LAYER_REGISTRY.get(lname)
            if lcls is None:
                continue
            inst = lcls()
            for fname, fval in ldata.get("fields", {}).items():
                try:
                    if isinstance(fval, dict) and "__bytes__" in fval:
                        fval = bytes.fromhex(fval["__bytes__"])
                    setattr(inst, fname, fval)
                except Exception:
                    pass
            ps.layers.append(inst)
        return ps

    def clone(self) -> "PacketStack":
        new = PacketStack(name=self.name)
        new.layers = [copy.deepcopy(l) for l in self.layers]
        return new

    def export_pcap(self, path: str) -> Tuple[bool, str]:
        pkt = self.build()
        if pkt is None:
            return False, "Empty packet"
        try:
            wrpcap(path, [pkt])
            return True, f"Written to {path}"
        except Exception as e:
            return False, str(e)


# ── Interface helpers ─────────────────────────────────────────────────────────
def list_interfaces() -> List[str]:
    if not SCAPY_AVAILABLE:
        return []
    try:
        return list(conf.ifaces.keys())
    except Exception:
        return []


def default_iface() -> str:
    if not SCAPY_AVAILABLE:
        return "lo"
    try:
        iface = conf.iface
        # Scapy may return a NetworkInterface object — force to string
        return str(iface.name) if hasattr(iface, "name") else str(iface) or "eth0"
    except Exception:
        return "eth0"


def capture_packets(
    iface: Optional[str] = None,
    count: int = 100,
    bpf: str = "",
    timeout: Optional[int] = None,
    prn: Any = None,
) -> List[Any]:
    if not SCAPY_AVAILABLE:
        return []
    try:
        return scapy.sniff(
            iface=iface, count=count, filter=bpf or None,
            timeout=timeout, prn=prn, store=True,
        )
    except Exception:
        return []
